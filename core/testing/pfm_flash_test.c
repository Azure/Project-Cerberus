// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_flash.h"
#include "manifest/pfm/pfm_format.h"
#include "mock/flash_master_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "engines/rsa_testing_engine.h"
#include "rsa_testing.h"
#include "pfm_testing.h"


static const char *SUITE = "pfm_flash";


/**
 * Dummy PFM for testing.
 */
const uint8_t PFM_DATA[] = {
	0x5c,0x03,0x4d,0x50,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x30,0x01,0x01,0x00,
	0x2c,0x01,0x07,0xff,0x45,0x23,0x01,0x00,0x01,0x01,0x00,0x00,0x54,0x65,0x73,0x74,
	0x69,0x6e,0x67,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x10,0x01,0x01,0x00,
	0x00,0x01,0x00,0x01,0x57,0x9d,0xf6,0xb7,0x7f,0x4b,0x27,0x2c,0xff,0xa9,0x78,0x13,
	0xfe,0x28,0x08,0x32,0x70,0xad,0xcf,0xf7,0x45,0x3a,0x88,0x6b,0x3d,0xc2,0x02,0x9a,
	0x09,0xdf,0x2f,0x94,0x13,0xd1,0xd3,0x41,0x28,0x62,0xb7,0x4f,0x35,0x93,0x47,0xcc,
	0xa3,0x31,0xe9,0x4a,0x0f,0x25,0xc8,0x70,0x4d,0x4b,0xb1,0xa5,0xfc,0xe7,0x3a,0x05,
	0xb5,0x51,0xae,0x5c,0xed,0x37,0x02,0xfc,0xca,0x3b,0x44,0x0a,0x63,0x72,0xbe,0xdb,
	0x08,0xb4,0x3c,0xb5,0x6b,0x95,0x83,0xe2,0xd1,0xd4,0x6f,0x4d,0x52,0xe6,0xc9,0xb6,
	0xf4,0x7e,0xe9,0x3d,0xff,0xca,0x87,0x9b,0x97,0x37,0xad,0xbf,0x3b,0x6f,0x0c,0x06,
	0xbf,0xfd,0xc8,0xcc,0xbc,0x97,0x90,0xca,0x1a,0xf6,0x70,0x22,0xc8,0x3e,0xb8,0x1c,
	0x24,0x75,0xde,0x38,0x30,0xba,0xf0,0xce,0x8d,0xdd,0x69,0x1f,0x3b,0xcc,0xde,0x1e,
	0xee,0x94,0x8f,0xb1,0x8a,0x45,0x61,0x28,0x0d,0xaa,0xbd,0xff,0x0f,0xaa,0x8b,0x69,
	0x45,0x4d,0xf4,0xa2,0x53,0x7d,0x73,0x61,0x96,0x03,0x91,0x4d,0x3c,0xe3,0xc8,0x95,
	0xbd,0x28,0x13,0x43,0xa8,0x51,0xc6,0xf5,0xfe,0x46,0x98,0x3f,0xcb,0x70,0xed,0xbe,
	0x36,0x49,0x31,0x4e,0xda,0x6e,0xeb,0x07,0xd2,0x84,0x70,0x20,0x44,0xb0,0x30,0x42,
	0xb3,0x7c,0x7e,0x04,0xa1,0x50,0x55,0x9f,0x52,0xf3,0xdf,0x46,0xab,0x91,0xc0,0x39,
	0x54,0x4f,0xe9,0x2b,0xb7,0x6d,0x1e,0x64,0x0f,0x28,0xc0,0x43,0xbb,0xf2,0xf6,0xe7,
	0x9e,0x37,0xd3,0x32,0x74,0xe8,0xb0,0x78,0x12,0xac,0x65,0xf2,0x80,0x6f,0x16,0xb7,
	0xcf,0xa2,0x7f,0xaa,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x10,0x01,0x01,0x00,
	0x0c,0x01,0x00,0x01,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0xc9,0x44,0x8c,0x40,
	0x6c,0x1f,0x64,0x8d,0xcb,0xa1,0xc7,0x3b,0x14,0xb4,0x89,0xd1,0x25,0x57,0x4a,0x5d,
	0xd5,0xaa,0x2c,0x1f,0x80,0x23,0x23,0xfc,0xc2,0xda,0xfc,0x7c,0xa6,0xad,0x35,0x83,
	0xab,0x92,0x1b,0x71,0x05,0xba,0x75,0x11,0x1e,0xdd,0x60,0x2a,0xe7,0xbe,0x91,0x3f,
	0xed,0xaa,0xe3,0x43,0x17,0x28,0x85,0x29,0xfd,0xb6,0x81,0x78,0x00,0xc0,0xe4,0xc1,
	0xb1,0x79,0x73,0x9e,0x91,0x5a,0x78,0x07,0x11,0x2a,0x24,0xd7,0xcc,0x22,0x35,0x2b,
	0xdf,0xbb,0xf7,0x62,0xdf,0x47,0x19,0xba,0x1f,0xbc,0x9a,0x5b,0x54,0xf5,0xa7,0x6a,
	0x39,0xcb,0x6b,0xe0,0xa5,0xb8,0x0a,0xa0,0x06,0x93,0xec,0xd8,0x03,0xbb,0x49,0x89,
	0xa8,0xfa,0x88,0x07,0x5e,0xc5,0x0f,0xad,0xb1,0xd1,0xa9,0x36,0x48,0x27,0x5f,0x40,
	0xa0,0x7c,0x2a,0x42,0x9c,0xdf,0x41,0x09,0x28,0xe0,0x05,0xad,0x51,0x44,0x96,0x98,
	0x34,0x7a,0x74,0xaa,0x9d,0xda,0x49,0x71,0xdd,0x6b,0xf0,0x74,0xf4,0x01,0xed,0x9d,
	0x42,0xd0,0x12,0x4a,0x63,0x7c,0xd0,0x6e,0x93,0x1f,0x9e,0xb6,0x40,0x93,0x23,0xa6,
	0x09,0xb7,0xac,0x2d,0x3e,0x79,0x8d,0x56,0x85,0x9f,0xc7,0x5a,0x58,0xa7,0x8f,0xdf,
	0x22,0x14,0x94,0x10,0x66,0xe6,0xd6,0xbb,0x2c,0x3f,0x05,0x63,0xb3,0x7a,0x64,0xf5,
	0x6d,0x52,0x82,0x82,0x3a,0x17,0x95,0x89,0xb1,0xb3,0x12,0x4d,0x21,0x64,0x4f,0x58,
	0xe9,0x4e,0x68,0xfa,0x5d,0x5e,0x80,0x49,0x78,0x70,0x4f,0x60,0xa3,0x59,0xca,0x3a,
	0xb0,0x04,0xb3,0xd2,0x34,0xae,0xac,0x7e,0xdc,0x17,0x16,0x81,0x10,0x00,0x09,0x00,
	0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x5e,0xdd,0xc1,0xba,
	0xb2,0x0f,0xa0,0xbd,0x72,0x61,0xee,0x77,0xd9,0xf4,0xf0,0xc2,0x0c,0x93,0xf9,0x1e,
	0x09,0x8c,0x4c,0x44,0x3d,0x38,0x86,0x69,0xc1,0x85,0x9b,0x5d,0x49,0xd4,0x94,0xa4,
	0xcd,0x1d,0xc1,0x64,0xd9,0x29,0xd4,0x42,0x28,0xe4,0xa3,0xd5,0x7e,0x71,0x03,0xe4,
	0x03,0xd8,0x67,0x8f,0x47,0x7b,0xc8,0xd8,0x80,0x0c,0x2f,0x9c,0xa6,0x63,0x96,0x9e,
	0x56,0xd2,0xe4,0x0d,0xf7,0xf5,0x70,0xda,0xa8,0x7b,0x5c,0xc6,0x76,0xbe,0xd0,0x6d,
	0x2b,0x34,0x42,0x92,0x81,0x44,0xe8,0x95,0x02,0x50,0x8e,0xa0,0x15,0x57,0x5c,0x7d,
	0x1f,0x54,0x1d,0xdd,0xb4,0xc2,0x2f,0x09,0x69,0xd2,0xc1,0xb6,0xa1,0x3f,0xee,0xc4,
	0x61,0x3d,0x3f,0xe0,0xa8,0x45,0x97,0xa5,0xd8,0xb1,0x2e,0x0a,0x63,0x8f,0x28,0x1d,
	0x58,0x01,0x77,0xc9,0x6c,0xc8,0x49,0x6f,0x61,0x15,0x2a,0xce,0x7d,0x0a,0x34,0xe6,
	0x92,0xd5,0x7b,0xed,0x2a,0x3c,0x3d,0xd0,0xd8,0x84,0xb4,0x4c,0x1a,0x17,0xfc,0x0f,
	0x4d,0x1f,0x4f,0x73,0xeb,0xef,0x91,0x75,0x82,0xfc,0x3f,0xbd,0xb5,0xbe,0xe1,0xcc,
	0x58,0x4d,0x1c,0x8c,0xf2,0x74,0x8d,0xd7,0x81,0xe1,0x83,0x50,0xcf,0x70,0xdf,0x38,
	0xf2,0x21,0xf8,0xeb,0xd8,0xb9,0x57,0x9d,0xc3,0x46,0x85,0x0f,0x88,0x67,0xee,0x32,
	0xc1,0x9f,0xd7,0x86,0x38,0xf4,0xb2,0x44,0x7d,0x10,0x67,0x7a,0x83,0x6f,0x53,0xbb,
	0x3f,0xcf,0xff,0x59,0x22,0x02,0x68,0x24,0xff,0x20,0xca,0x02,0x8a,0xc2,0x8c,0x77,
	0xb1,0x79,0x90,0x78,0xec,0xee,0xf4,0xf8,0xef,0xb9,0x01,0xb2
};

/**
 * Length of the test PFM data.
 */
const uint32_t PFM_DATA_LEN = sizeof (PFM_DATA);

/**
 * PFM_DATA hash for testing.
 */
const uint8_t PFM_HASH[] = {
	0x7b,0xf1,0x6e,0xc8,0x8b,0x50,0xfb,0x61,0xe4,0x85,0x82,0x0a,0x2e,0x82,0xec,0x08,
	0x09,0x49,0x72,0xb4,0x23,0xad,0xbc,0x7e,0xa1,0xe6,0x03,0x8d,0xe9,0x54,0x47,0xc2
};

/**
 * Length of the test PFM hash.
 */
const uint32_t PFM_HASH_LEN = sizeof (PFM_HASH);


/* Test PFM components. */

/**
 * The length of the PFM signature.
 */
const size_t PFM_SIGNATURE_LEN = 256;

/**
 * The offset from the base for the PFM signature.
 */
const uint32_t PFM_SIGNATURE_OFFSET = (sizeof (PFM_DATA) - 256);

/**
 * The signature for the PFM.
 */
const uint8_t *PFM_SIGNATURE = PFM_DATA + (sizeof (PFM_DATA) - 256);

/**
 * The address offset for the allow versions header.
 */
const size_t PFM_ALLOWED_HDR_OFFSET = PFM_HEADER_SIZE;

/**
 * The offset of the firmware header in the PFM.
 */
const size_t PFM_FW_HEADER_OFFSET = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;

/**
 * The address offset for the version identifier.
 */
const size_t PFM_VERSION_OFFSET = 0x1c;

/**
 * The version identifier in the PFM data.
 */
const char *PFM_VERSION_ID = "Testing";

/**
 * The offset of the defined read/write region.
 */
#define	PFM_RW_REGION_OFFSET	0x24

/**
 * The address offset for image header in the PFM.
 */
#define	PFM_IMG_HEADER_OFFSET	0x2c

/**
 * The address offset for the image flags.
 */
#define	PFM_IMG_FLAGS_OFFSET	PFM_IMG_HEADER_OFFSET + 2

/**
 * The address offset for the image signature in the PFM.
 */
#define	PFM_IMG_SIG_OFFSET		PFM_IMG_HEADER_OFFSET + PFM_IMG_HEADER_SIZE

/**
 * The image signature data in the PFM.
 */
static const uint8_t *PFM_IMG_SIGNATURE = PFM_DATA + PFM_IMG_SIG_OFFSET;

/**
 * The address offset for the firmware image region in the PFM.
 */
#define	PFM_IMG_REGION_OFFSET	PFM_IMG_SIG_OFFSET + PFM_IMG_KEY_SIZE

/**
 * The address offset for the start of the key manifest.
 */
#define	PFM_MANIFEST_ADDRESS		0x13c
const size_t PFM_MANIFEST_OFFSET = PFM_MANIFEST_ADDRESS;

/**
 * The address offset for the key header in the PFM.
 */
#define	PFM_KEY_HEADER_OFFSET	PFM_MANIFEST_ADDRESS + PFM_MANIFEST_HEADER_SIZE

/**
 * The address offset for the image key in the PFM.
 */
#define	PFM_IMG_KEY_OFFSET		PFM_KEY_HEADER_OFFSET + PFM_KEY_HEADER_SIZE

/**
 * The image key data in the PFM.
 */
static const uint8_t *PFM_IMG_KEY = PFM_DATA + PFM_IMG_KEY_OFFSET;

/**
 * The address offset of the start of the platform ID header.
 */
const size_t PFM_PLATFORM_HEADER_OFFSET = 0x24c;

/**
 * The address offset of the start of the platform identifier.
 */
const size_t PFM_PLATFORM_ID_OFFSET = 0x250;

/**
 * The platform identifier in the PFM data.
 */
const char *PFM_PLATFORM_ID = "PFM Test1";


/*******************
 * Test cases
 *******************/

static void pfm_flash_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, pfm.base.base.verify);
	CuAssertPtrNotNull (test, pfm.base.base.get_id);
	CuAssertPtrNotNull (test, pfm.base.base.get_hash);
	CuAssertPtrNotNull (test, pfm.base.base.get_signature);
	CuAssertPtrNotNull (test, pfm.base.get_platform_id);
	CuAssertPtrNotNull (test, pfm.base.get_supported_versions);
	CuAssertPtrNotNull (test, pfm.base.free_fw_versions);
	CuAssertPtrNotNull (test, pfm.base.get_read_write_regions);
	CuAssertPtrNotNull (test, pfm.base.free_read_write_regions);
	CuAssertPtrNotNull (test, pfm.base.get_firmware_images);
	CuAssertPtrNotNull (test, pfm.base.free_firmware_images);

	CuAssertIntEquals (test, 0x10000, pfm_flash_get_addr (&pfm));
	CuAssertPtrEquals (test, &flash, pfm_flash_get_flash (&pfm));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (NULL, &flash, 0x10000);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm_flash_init (&pfm, NULL, 0x10000);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_init_not_block_aligned (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10001);
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void pfm_flash_test_release_null (CuTest *test)
{
	TEST_START;

	pfm_flash_release (NULL);
}

static void pfm_flash_test_release_no_init (CuTest *test)
{
	struct pfm_flash pfm;

	TEST_START;

	memset (&pfm, 0, sizeof (pfm));

	pfm_flash_release (&pfm);
}

static void pfm_flash_test_get_addr_null (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, 0, pfm_flash_get_addr (NULL));
}

static void pfm_flash_test_get_flash_null (CuTest *test)
{
	TEST_START;

	CuAssertPtrEquals (test, NULL, pfm_flash_get_flash (NULL));
}

static void pfm_flash_test_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		PFM_DATA + PFM_PLATFORM_HEADER_OFFSET, PFM_DATA_LEN - PFM_PLATFORM_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_PLATFORM_HEADER_OFFSET, 0, -1,
			PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_empty_manifest (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	const char *platform_id = "Platform";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_platform_header *platform_header;
	int man_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int plat_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + 8;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE;
	manifest_header->key_count = 0;

	platform_header = (struct pfm_platform_header*) &pfm_data[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + 8;
	platform_header->id_length = strlen (platform_id);
	memcpy (&pfm_data[plat_offset + PFM_PLATFORM_HEADER_SIZE], platform_id, strlen (platform_id));

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) platform_header,
		platform_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (NULL, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.base.verify (&pfm.base.base, NULL, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, NULL, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_allowable_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_manifest_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_platform_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_missing_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int img_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset2 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int img_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset3 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;
	int sig_offset = key_offset + PFM_IMG_KEY_SIZE;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset2] = 22;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8 + img_header->length;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset3] = 33;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_MALFORMED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_header_reserved_non_zero (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	const char *platform_id = "Platform";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	struct pfm_platform_header *platform_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int img_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset2 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int img_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset3 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;
	int plat_offset = key_offset + PFM_IMG_KEY_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + 8;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;
	header->reserved = 1;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset2] = 22;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8 + img_header->length;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset3] = 33;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	platform_header = (struct pfm_platform_header*) &pfm_data[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + 8;
	memcpy (&pfm_data[plat_offset + PFM_PLATFORM_HEADER_SIZE], platform_id, strlen (platform_id));

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) platform_header,
		platform_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_allowable_header_reserved_non_zero (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	const char *platform_id = "Platform";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	struct pfm_platform_header *platform_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int img_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset2 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int img_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset3 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;
	int plat_offset = key_offset + PFM_IMG_KEY_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + 8;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;
	allowed_header->reserved = 1;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset2] = 22;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8 + img_header->length;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset3] = 33;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	platform_header = (struct pfm_platform_header*) &pfm_data[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + 8;
	memcpy (&pfm_data[plat_offset + PFM_PLATFORM_HEADER_SIZE], platform_id, strlen (platform_id));

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) platform_header,
		platform_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_manifest_header_reserved_non_zero (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	const char *platform_id = "Platform";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	struct pfm_platform_header *platform_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int img_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset2 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int img_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset3 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;
	int plat_offset = key_offset + PFM_IMG_KEY_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + 8;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset2] = 22;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8 + img_header->length;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset3] = 33;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;
	manifest_header->reserved = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	platform_header = (struct pfm_platform_header*) &pfm_data[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + 8;
	memcpy (&pfm_data[plat_offset + PFM_PLATFORM_HEADER_SIZE], platform_id, strlen (platform_id));

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) platform_header,
		platform_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_verify_platform_header_reserved_non_zero (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	const char *platform_id = "Platform";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	struct pfm_platform_header *platform_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int img_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset2 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int img_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset3 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;
	int plat_offset = key_offset + PFM_IMG_KEY_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + 8;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset2] = 22;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8 + img_header->length;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset3] = 33;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	platform_header = (struct pfm_platform_header*) &pfm_data[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + 8;
	platform_header->reserved = 1;
	memcpy (&pfm_data[plat_offset + PFM_PLATFORM_HEADER_SIZE], platform_id, strlen (platform_id));

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) platform_header,
		platform_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_get_id (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_id (&pfm.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);
	spi_flash_release (&flash);
}

static void pfm_flash_test_get_id_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.base.get_id (&pfm.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_id_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	uint32_t id;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_id (&pfm.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_hash (&pfm.base.base, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_get_hash_after_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));
	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	/* Structure verification. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		PFM_DATA + PFM_PLATFORM_HEADER_OFFSET, PFM_DATA_LEN - PFM_PLATFORM_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_PLATFORM_HEADER_OFFSET, 0, -1,
			PFM_PLATFORM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.verify (&pfm.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_hash (&pfm.base.base, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
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

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_hash (NULL, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.base.get_hash (&pfm.base.base, NULL, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pfm.base.base.get_hash (&pfm.base.base, &hash.base, NULL, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_get_hash_bad_magic_num (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_hash (&pfm.base.base, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_flash_test_get_signature (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_signature (&pfm.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_signature_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.base.get_signature (&pfm.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.base.get_signature (&pfm.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, fw.count);
	CuAssertPtrNotNull (test, fw.versions);
	CuAssertStrEquals (test, PFM_VERSION_ID, fw.versions[0].fw_version_id);
	CuAssertIntEquals (test, 0x12345, fw.versions[0].version_addr);
	CuAssertIntEquals (test, 0xff, fw.versions[0].blank_byte);

	pfm.base.free_fw_versions (&pfm.base, &fw);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_multiple (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;
	const char *version1 = "Version1";
	const char *version2 = "Version2";
	const char *version3 = "Version3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(strlen (version1) * 3)];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	int offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int offset2 = offset1 + PFM_FW_HEADER_SIZE + strlen (version1);
	int offset3 = offset2 + PFM_FW_HEADER_SIZE + strlen (version2);

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version1);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	memcpy (&pfm_data[offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header += fw_header->length;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version2);
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->blank_byte = 0x55;
	memcpy (&pfm_data[offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header += fw_header->length;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version3);
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->blank_byte = 0xaa;
	memcpy (&pfm_data[offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header += fw_header->length;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + offset1,
		sizeof (pfm_data) - offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + offset1 + PFM_FW_HEADER_SIZE, sizeof (pfm_data) - offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset1 + PFM_FW_HEADER_SIZE, 0, -1, strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + offset2,
		sizeof (pfm_data) - offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset2, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + offset2 + PFM_FW_HEADER_SIZE, sizeof (pfm_data) - offset2 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset2 + PFM_FW_HEADER_SIZE, 0, -1, strlen (version2)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + offset3,
		sizeof (pfm_data) - offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset3, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + offset3 + PFM_FW_HEADER_SIZE, sizeof (pfm_data) - offset3 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset3 + PFM_FW_HEADER_SIZE, 0, -1, strlen (version3)));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, fw.count);
	CuAssertPtrNotNull (test, fw.versions);

	CuAssertStrEquals (test, version1, fw.versions[0].fw_version_id);
	CuAssertIntEquals (test, 0x12345, fw.versions[0].version_addr);
	CuAssertIntEquals (test, 0, fw.versions[0].blank_byte);
	CuAssertStrEquals (test, version2, fw.versions[1].fw_version_id);
	CuAssertIntEquals (test, 0x6789, fw.versions[1].version_addr);
	CuAssertIntEquals (test, 0x55, fw.versions[1].blank_byte);
	CuAssertStrEquals (test, version3, fw.versions[2].fw_version_id);
	CuAssertIntEquals (test, 0x112233, fw.versions[2].version_addr);
	CuAssertIntEquals (test, 0xaa, fw.versions[2].blank_byte);

	pfm.base.free_fw_versions (&pfm.base, &fw);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_empty_manifest (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, fw.count);
	CuAssertPtrEquals (test, NULL, (void*) fw.versions);

	pfm.base.free_fw_versions (&pfm.base, &fw);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (NULL, &fw);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_supported_versions (&pfm.base, NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_allowable_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_fw_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;
	const char *version1 = "Version1";
	const char *version2 = "Version2";
	const char *version3 = "Version3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(strlen (version1) * 3)];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	int offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int offset2 = offset1 + PFM_FW_HEADER_SIZE + strlen (version1);
	int offset3 = offset2 + PFM_FW_HEADER_SIZE + strlen (version2);

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version1);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	memcpy (&pfm_data[offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version2);
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	memcpy (&pfm_data[offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version3);
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	memcpy (&pfm_data[offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + offset1,
		sizeof (pfm_data) - offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + offset1 + PFM_FW_HEADER_SIZE, sizeof (pfm_data) - offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset1 + PFM_FW_HEADER_SIZE, 0, -1, strlen (version1)));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_id_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;
	const char *version1 = "Version1";
	const char *version2 = "Version2";
	const char *version3 = "Version3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(strlen (version1) * 3)];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	int offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int offset2 = offset1 + PFM_FW_HEADER_SIZE + strlen (version1);
	int offset3 = offset2 + PFM_FW_HEADER_SIZE + strlen (version2);

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version1);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	memcpy (&pfm_data[offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version2);
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	memcpy (&pfm_data[offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;

	fw_header = (struct pfm_firmware_header*) &pfm_data[offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + strlen (version3);
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	memcpy (&pfm_data[offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + offset1,
		sizeof (pfm_data) - offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + offset1 + PFM_FW_HEADER_SIZE, sizeof (pfm_data) - offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset1 + PFM_FW_HEADER_SIZE, 0, -1, strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + offset2,
		sizeof (pfm_data) - offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + offset2, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_supported_versions_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_supported_versions (&pfm.base, &fw);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_free_fw_versions_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	pfm.base.free_fw_versions (&pfm.base, NULL);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_free_fw_versions_null_list (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_firmware_versions fw;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	fw.count = 1;
	fw.versions = NULL;
	pfm.base.free_fw_versions (&pfm.base, &fw);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_RW_REGION_OFFSET,
		PFM_DATA_LEN - PFM_RW_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_RW_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Testing", &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertIntEquals (test, 0x2000000, writable.regions[0].start_addr);
	CuAssertIntEquals (test, 0x2000000, writable.regions[0].length);

	pfm.base.free_read_write_regions (&pfm.base, &writable);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_wrong_version (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "gnitseT", &writable);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_version_diff_len (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Short", &writable);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_multiple_versions (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(PFM_REGION_SIZE * 3) + 25];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_flash_region *region;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int reg_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int reg_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int reg_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + PFM_REGION_SIZE;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset2,
		sizeof (pfm_data) - ver_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset2, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset2 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset2 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset2 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version2)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset2,
		sizeof (pfm_data) - reg_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset2, 0, -1, PFM_REGION_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, version2, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertIntEquals (test, 0x2000000, writable.regions[0].start_addr);
	CuAssertIntEquals (test, 0x800000, writable.regions[0].length);

	pfm.base.free_read_write_regions (&pfm.base, &writable);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_multiple_regions (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	const char *version = "V 3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE +
		(PFM_REGION_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_flash_region *region;
	int ver_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int reg_offset1 = ver_offset + PFM_FW_HEADER_SIZE + 4;
	int reg_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int reg_offset3 = reg_offset2 + PFM_REGION_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + (PFM_REGION_SIZE * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version);
	fw_header->rw_count = 3;
	memcpy (&pfm_data[ver_offset + PFM_FW_HEADER_SIZE], version, strlen (version));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset,
		sizeof (pfm_data) - ver_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset1,
		sizeof (pfm_data) - reg_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset1, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset2,
		sizeof (pfm_data) - reg_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset2, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset3,
		sizeof (pfm_data) - reg_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset3, 0, -1, PFM_REGION_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, version, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, writable.count);
	CuAssertPtrNotNull (test, writable.regions);

	CuAssertIntEquals (test, 0x1000000, writable.regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, writable.regions[0].length);
	CuAssertIntEquals (test, 0x2000000, writable.regions[1].start_addr);
	CuAssertIntEquals (test, 0x800000, writable.regions[1].length);
	CuAssertIntEquals (test, 0x4000000, writable.regions[2].start_addr);
	CuAssertIntEquals (test, 0x20000, writable.regions[2].length);

	pfm.base.free_read_write_regions (&pfm.base, &writable);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_empty_manifest (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Testing", &writable);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (NULL, "Testing", &writable);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_read_write_regions (&pfm.base, NULL, &writable);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "", &writable);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Testing", NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);
	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Testing", &writable);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);
	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_allowable_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Testing", &writable);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);
	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_fw_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(PFM_REGION_SIZE * 3) + 25];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_flash_region *region;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int reg_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int reg_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int reg_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + PFM_REGION_SIZE;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, version2, &writable);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);
	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_version_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(PFM_REGION_SIZE * 3) + 25];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_flash_region *region;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int reg_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int reg_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int reg_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + PFM_REGION_SIZE;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->rw_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset2,
		sizeof (pfm_data) - ver_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset2, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, version2, &writable);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);
	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_region_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	const char *version = "V 3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE +
		(PFM_REGION_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_flash_region *region;
	int ver_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int reg_offset1 = ver_offset + PFM_FW_HEADER_SIZE + 4;
	int reg_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int reg_offset3 = reg_offset2 + PFM_REGION_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + (PFM_REGION_SIZE * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version);
	fw_header->rw_count = 3;
	memcpy (&pfm_data[ver_offset + PFM_FW_HEADER_SIZE], version, strlen (version));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset,
		sizeof (pfm_data) - ver_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset1,
		sizeof (pfm_data) - reg_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset1, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, version, &writable);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_read_write_regions_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_read_write_regions writable;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_read_write_regions (&pfm.base, "Testing", &writable);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_free_read_write_regions_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	pfm.base.free_read_write_regions (&pfm.base, NULL);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_REGION_OFFSET,
		PFM_DATA_LEN - PFM_IMG_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_KEY_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_KEY_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_KEY_HEADER_OFFSET, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_KEY, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_KEY_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 1, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 0, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[0].length);

	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	status = testing_validate_array (PFM_IMG_KEY, img_list.images[0].key.modulus, PFM_IMG_KEY_SIZE);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	status = testing_validate_array (PFM_IMG_SIGNATURE, img_list.images[0].signature,
		PFM_IMG_KEY_SIZE);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_no_flags (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	uint8_t pfm_data[PFM_DATA_LEN];

	TEST_START;

	memcpy (pfm_data, PFM_DATA, sizeof (pfm_data));
	pfm_data[PFM_IMG_FLAGS_OFFSET] = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_ALLOWED_HDR_OFFSET,
		sizeof (pfm_data) - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_FW_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_VERSION_OFFSET,
		sizeof (pfm_data) - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_IMG_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_IMG_REGION_OFFSET,
		sizeof (pfm_data) - PFM_IMG_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_MANIFEST_OFFSET,
		sizeof (pfm_data) - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_KEY_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_KEY_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_KEY_HEADER_OFFSET, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_KEY, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_KEY_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 1, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 0, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 0, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[0].length);

	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	status = testing_validate_array (PFM_IMG_KEY, img_list.images[0].key.modulus, PFM_IMG_KEY_SIZE);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	status = testing_validate_array (PFM_IMG_SIGNATURE, img_list.images[0].signature,
		PFM_IMG_KEY_SIZE);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_unknown_flags (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	uint8_t pfm_data[PFM_DATA_LEN];

	TEST_START;

	memcpy (pfm_data, PFM_DATA, sizeof (pfm_data));
	pfm_data[PFM_IMG_FLAGS_OFFSET] = 8;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_ALLOWED_HDR_OFFSET,
		sizeof (pfm_data) - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_FW_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_VERSION_OFFSET,
		sizeof (pfm_data) - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_IMG_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_IMG_REGION_OFFSET,
		sizeof (pfm_data) - PFM_IMG_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_MANIFEST_OFFSET,
		sizeof (pfm_data) - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_KEY_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_KEY_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_KEY_HEADER_OFFSET, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_KEY, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_KEY_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 1, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 0, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 0, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[0].length);

	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	status = testing_validate_array (PFM_IMG_KEY, img_list.images[0].key.modulus, PFM_IMG_KEY_SIZE);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	status = testing_validate_array (PFM_IMG_SIGNATURE, img_list.images[0].signature,
		PFM_IMG_KEY_SIZE);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_no_version_padding (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	uint8_t pfm_data[PFM_DATA_LEN];

	TEST_START;

	memcpy (pfm_data, PFM_DATA, sizeof (pfm_data));
	pfm_data[PFM_FW_HEADER_OFFSET + 2] = 8;
	pfm_data[PFM_VERSION_OFFSET + strlen (PFM_VERSION_ID)] = '1';

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_ALLOWED_HDR_OFFSET,
		sizeof (pfm_data) - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_FW_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_VERSION_OFFSET,
		sizeof (pfm_data) - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_IMG_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_IMG_REGION_OFFSET,
		sizeof (pfm_data) - PFM_IMG_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_MANIFEST_OFFSET,
		sizeof (pfm_data) - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_KEY_HEADER_OFFSET,
		sizeof (pfm_data) - PFM_KEY_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_KEY_HEADER_OFFSET, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_KEY, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_KEY_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing1", &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 1, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 0, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[0].length);

	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	status = testing_validate_array (PFM_IMG_KEY, img_list.images[0].key.modulus, PFM_IMG_KEY_SIZE);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	status = testing_validate_array (PFM_IMG_SIGNATURE, img_list.images[0].signature,
		PFM_IMG_KEY_SIZE);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_unknown_version (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Bad", &img_list);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_multiple_versions (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	const char *version2 = "Version2";
	const char *version3 = "V 3";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + (PFM_FW_HEADER_SIZE * 3) +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_REGION_SIZE * 3) + PFM_MANIFEST_HEADER_SIZE +
		PFM_KEY_HEADER_SIZE + (PFM_IMG_KEY_SIZE * 4) + 25];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int ver_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int img_offset2 = ver_offset2 + PFM_FW_HEADER_SIZE + 8;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset2 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int ver_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int img_offset3 = ver_offset3 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset3 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset2] = 22;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset2];
	fw_header->length = PFM_FW_HEADER_SIZE + 8 + img_header->length;
	fw_header->version_addr = 0x6789;
	fw_header->version_length = strlen (version2);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset2 + PFM_FW_HEADER_SIZE], version2, strlen (version2));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset3] = 33;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset3];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x112233;
	fw_header->version_length = strlen (version3);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset3 + PFM_FW_HEADER_SIZE], version3, strlen (version3));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset2,
		sizeof (pfm_data) - ver_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset2, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset2 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset2 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset2 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version2)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset2,
		sizeof (pfm_data) - reg_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset2, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset,
		sizeof (pfm_data) - pub_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset,
		sizeof (pfm_data) - key_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version2, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 1, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 0, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x800000, img_list.images[0].regions[0].length);

	CuAssertIntEquals (test, 3, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	CuAssertIntEquals (test, 1, img_list.images[0].key.modulus[0]);

	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	CuAssertIntEquals (test, 22, img_list.images[0].signature[0]);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_multiple_regions (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE +
		PFM_IMG_HEADER_SIZE + (PFM_REGION_SIZE * 3) + PFM_MANIFEST_HEADER_SIZE +
		PFM_KEY_HEADER_SIZE + (PFM_IMG_KEY_SIZE * 2) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int reg_offset2 = reg_offset1 + PFM_REGION_SIZE;
	int reg_offset3 = reg_offset2 + PFM_REGION_SIZE;
	int man_offset = reg_offset3 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	region = (struct pfm_flash_region*) &pfm_data[reg_offset2];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;

	region = (struct pfm_flash_region*) &pfm_data[reg_offset3];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset1,
		sizeof (pfm_data) - reg_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset1, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset2,
		sizeof (pfm_data) - reg_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset2, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset3,
		sizeof (pfm_data) - reg_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset3, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset,
		sizeof (pfm_data) - pub_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset,
		sizeof (pfm_data) - key_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 3, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	CuAssertIntEquals (test, 1, img_list.images[0].key.modulus[0]);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	CuAssertIntEquals (test, 11, img_list.images[0].signature[0]);

	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].length);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[1].start_addr);
	CuAssertIntEquals (test, 0x800000, img_list.images[0].regions[1].length);
	CuAssertIntEquals (test, 0x4000000, img_list.images[0].regions[2].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[0].regions[2].length);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_multiple_images (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE  +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_IMG_KEY_SIZE * 4) + (PFM_REGION_SIZE * 3 * 3) +
		PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset11 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int reg_offset12 = reg_offset11 + PFM_REGION_SIZE;
	int reg_offset13 = reg_offset12 + PFM_REGION_SIZE;
	int img_offset2 = reg_offset13 + PFM_REGION_SIZE;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset21 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int reg_offset22 = reg_offset21 + PFM_REGION_SIZE;
	int img_offset3 = reg_offset22 + PFM_REGION_SIZE;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset31 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int reg_offset32 = reg_offset31 + PFM_REGION_SIZE;
	int reg_offset33 = reg_offset32 + PFM_REGION_SIZE;
	int reg_offset34 = reg_offset33 + PFM_REGION_SIZE;
	int man_offset = reg_offset34 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 +
		((PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3)) * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 3;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset11];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset12];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset13];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 2);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 2;
	pfm_data[sig_offset2] = 22;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset21];
	region->start_addr = 0x20000;
	region->end_addr = 0x3ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset22];
	region->start_addr = 0x50000;
	region->end_addr = 0x6ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 4);
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 4;
	pfm_data[sig_offset3] = 33;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset31];
	region->start_addr = 0x6000000;
	region->end_addr = 0x6ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset32];
	region->start_addr = 0x500000;
	region->end_addr = 0x6fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset33];
	region->start_addr = 0x40000;
	region->end_addr = 0x4ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset34];
	region->start_addr = 0x100000;
	region->end_addr = 0x5fffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset11,
		sizeof (pfm_data) - reg_offset11,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset11, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset12,
		sizeof (pfm_data) - reg_offset12,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset12, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset13,
		sizeof (pfm_data) - reg_offset13,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset13, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset21,
		sizeof (pfm_data) - reg_offset21,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset21, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset22,
		sizeof (pfm_data) - reg_offset22,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset22, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset3,
		sizeof (pfm_data) - img_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset3, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset3,
		sizeof (pfm_data) - sig_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset31,
		sizeof (pfm_data) - reg_offset31,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset31, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset32,
		sizeof (pfm_data) - reg_offset32,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset32, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset33,
		sizeof (pfm_data) - reg_offset33,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset33, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset34,
		sizeof (pfm_data) - reg_offset34,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset34, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset,
		sizeof (pfm_data) - pub_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset,
		sizeof (pfm_data) - key_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 3, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[0].key.modulus[0]);
	CuAssertIntEquals (test, 11, img_list.images[0].signature[0]);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].length);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[1].start_addr);
	CuAssertIntEquals (test, 0x800000, img_list.images[0].regions[1].length);
	CuAssertIntEquals (test, 0x4000000, img_list.images[0].regions[2].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[0].regions[2].length);

	CuAssertIntEquals (test, 2, img_list.images[1].count);
	CuAssertPtrNotNull (test, img_list.images[1].regions);
	CuAssertIntEquals (test, 1, img_list.images[1].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[1].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[1].key.modulus[0]);
	CuAssertIntEquals (test, 22, img_list.images[1].signature[0]);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].length);
	CuAssertIntEquals (test, 0x50000, img_list.images[1].regions[1].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[1].length);

	CuAssertIntEquals (test, 4, img_list.images[2].count);
	CuAssertPtrNotNull (test, img_list.images[2].regions);
	CuAssertIntEquals (test, 0, img_list.images[2].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[2].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[2].key.modulus[0]);
	CuAssertIntEquals (test, 33, img_list.images[2].signature[0]);
	CuAssertIntEquals (test, 0x6000000, img_list.images[2].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[2].regions[0].length);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[1].start_addr);
	CuAssertIntEquals (test, 0x200000, img_list.images[2].regions[1].length);
	CuAssertIntEquals (test, 0x40000, img_list.images[2].regions[2].start_addr);
	CuAssertIntEquals (test, 0x10000, img_list.images[2].regions[2].length);
	CuAssertIntEquals (test, 0x100000, img_list.images[2].regions[3].start_addr);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[3].length);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_multiple_keys (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE  +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_IMG_KEY_SIZE * 6) + (PFM_REGION_SIZE * 3 * 3) +
		PFM_MANIFEST_HEADER_SIZE + (PFM_KEY_HEADER_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset11 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int reg_offset12 = reg_offset11 + PFM_REGION_SIZE;
	int reg_offset13 = reg_offset12 + PFM_REGION_SIZE;
	int img_offset2 = reg_offset13 + PFM_REGION_SIZE;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset21 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int reg_offset22 = reg_offset21 + PFM_REGION_SIZE;
	int img_offset3 = reg_offset22 + PFM_REGION_SIZE;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset31 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int reg_offset32 = reg_offset31 + PFM_REGION_SIZE;
	int reg_offset33 = reg_offset32 + PFM_REGION_SIZE;
	int reg_offset34 = reg_offset33 + PFM_REGION_SIZE;
	int man_offset = reg_offset34 + PFM_REGION_SIZE;
	int pub_offset1 = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset1 = pub_offset1 + PFM_KEY_HEADER_SIZE;
	int pub_offset2 = key_offset1 + PFM_IMG_KEY_SIZE;
	int key_offset2 = pub_offset2 + PFM_KEY_HEADER_SIZE;
	int pub_offset3 = key_offset2 + PFM_IMG_KEY_SIZE;
	int key_offset3 = pub_offset3 + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 +
		((PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3)) * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 3;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset11];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset12];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset13];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 2);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 1;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 2;
	pfm_data[sig_offset2] = 22;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset21];
	region->start_addr = 0x20000;
	region->end_addr = 0x3ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset22];
	region->start_addr = 0x50000;
	region->end_addr = 0x6ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 4);
	img_header->flags = 0;
	img_header->key_id = 2;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 4;
	pfm_data[sig_offset3] = 33;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset31];
	region->start_addr = 0x6000000;
	region->end_addr = 0x6ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset32];
	region->start_addr = 0x500000;
	region->end_addr = 0x6fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset33];
	region->start_addr = 0x40000;
	region->end_addr = 0x4ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset34];
	region->start_addr = 0x100000;
	region->end_addr = 0x5fffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE +
		((PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE) * 3);
	manifest_header->key_count = 3;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset1];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset1] = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset2];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 1;
	pfm_data[key_offset2] = 2;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset3];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 2;
	pfm_data[key_offset3] = 3;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset11,
		sizeof (pfm_data) - reg_offset11,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset11, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset12,
		sizeof (pfm_data) - reg_offset12,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset12, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset13,
		sizeof (pfm_data) - reg_offset13,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset13, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset21,
		sizeof (pfm_data) - reg_offset21,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset21, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset22,
		sizeof (pfm_data) - reg_offset22,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset22, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset3,
		sizeof (pfm_data) - img_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset3, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset3,
		sizeof (pfm_data) - sig_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset31,
		sizeof (pfm_data) - reg_offset31,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset31, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset32,
		sizeof (pfm_data) - reg_offset32,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset32, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset33,
		sizeof (pfm_data) - reg_offset33,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset33, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset34,
		sizeof (pfm_data) - reg_offset34,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset34, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset1,
		sizeof (pfm_data) - pub_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset1, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset1,
		sizeof (pfm_data) - key_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset2,
		sizeof (pfm_data) - pub_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset2, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset2,
		sizeof (pfm_data) - key_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset3,
		sizeof (pfm_data) - pub_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset3, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset3,
		sizeof (pfm_data) - key_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 3, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[0].key.modulus[0]);
	CuAssertIntEquals (test, 11, img_list.images[0].signature[0]);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].length);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[1].start_addr);
	CuAssertIntEquals (test, 0x800000, img_list.images[0].regions[1].length);
	CuAssertIntEquals (test, 0x4000000, img_list.images[0].regions[2].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[0].regions[2].length);

	CuAssertIntEquals (test, 2, img_list.images[1].count);
	CuAssertPtrNotNull (test, img_list.images[1].regions);
	CuAssertIntEquals (test, 1, img_list.images[1].always_validate);
	CuAssertIntEquals (test, 3, img_list.images[1].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].sig_length);
	CuAssertIntEquals (test, 2, img_list.images[1].key.modulus[0]);
	CuAssertIntEquals (test, 22, img_list.images[1].signature[0]);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].length);
	CuAssertIntEquals (test, 0x50000, img_list.images[1].regions[1].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[1].length);

	CuAssertIntEquals (test, 4, img_list.images[2].count);
	CuAssertPtrNotNull (test, img_list.images[2].regions);
	CuAssertIntEquals (test, 0, img_list.images[2].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[2].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].sig_length);
	CuAssertIntEquals (test, 3, img_list.images[2].key.modulus[0]);
	CuAssertIntEquals (test, 33, img_list.images[2].signature[0]);
	CuAssertIntEquals (test, 0x6000000, img_list.images[2].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[2].regions[0].length);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[1].start_addr);
	CuAssertIntEquals (test, 0x200000, img_list.images[2].regions[1].length);
	CuAssertIntEquals (test, 0x40000, img_list.images[2].regions[2].start_addr);
	CuAssertIntEquals (test, 0x10000, img_list.images[2].regions[2].length);
	CuAssertIntEquals (test, 0x100000, img_list.images[2].regions[3].start_addr);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[3].length);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_key_id_matches_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE  +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_IMG_KEY_SIZE * 4) + 64 + (PFM_REGION_SIZE * 3 * 3) +
		PFM_MANIFEST_HEADER_SIZE + (PFM_KEY_HEADER_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset11 = sig_offset1 + 32;
	int reg_offset12 = reg_offset11 + PFM_REGION_SIZE;
	int reg_offset13 = reg_offset12 + PFM_REGION_SIZE;
	int img_offset2 = reg_offset13 + PFM_REGION_SIZE;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset21 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int reg_offset22 = reg_offset21 + PFM_REGION_SIZE;
	int img_offset3 = reg_offset22 + PFM_REGION_SIZE;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset31 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int reg_offset32 = reg_offset31 + PFM_REGION_SIZE;
	int reg_offset33 = reg_offset32 + PFM_REGION_SIZE;
	int reg_offset34 = reg_offset33 + PFM_REGION_SIZE;
	int man_offset = reg_offset34 + PFM_REGION_SIZE;
	int pub_offset1 = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset1 = pub_offset1 + PFM_KEY_HEADER_SIZE;
	int pub_offset2 = key_offset1 + 32;
	int key_offset2 = pub_offset2 + PFM_KEY_HEADER_SIZE;
	int pub_offset3 = key_offset2 + PFM_IMG_KEY_SIZE;
	int key_offset3 = pub_offset3 + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + (PFM_IMG_HEADER_SIZE * 3) +
		(PFM_IMG_KEY_SIZE * 2) + (PFM_REGION_SIZE * 3 * 3) + 32;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 3;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + 32 + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = 32;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset11];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset12];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset13];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 2);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 1;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 2;
	pfm_data[sig_offset2] = 22;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset21];
	region->start_addr = 0x20000;
	region->end_addr = 0x3ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset22];
	region->start_addr = 0x50000;
	region->end_addr = 0x6ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 4);
	img_header->flags = 0;
	img_header->key_id = 32;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 4;
	pfm_data[sig_offset3] = 33;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset31];
	region->start_addr = 0x6000000;
	region->end_addr = 0x6ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset32];
	region->start_addr = 0x500000;
	region->end_addr = 0x6fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset33];
	region->start_addr = 0x40000;
	region->end_addr = 0x4ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset34];
	region->start_addr = 0x100000;
	region->end_addr = 0x5fffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + (PFM_KEY_HEADER_SIZE * 3)  +
		(PFM_IMG_KEY_SIZE * 2) + 32;
	manifest_header->key_count = 3;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset1];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = 32;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset1] = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset2];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 1;
	pfm_data[key_offset2] = 2;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset3];
	key_header->length = PFM_KEY_HEADER_SIZE + 32;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 32;
	pfm_data[key_offset3] = 3;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, 32));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset11,
		sizeof (pfm_data) - reg_offset11,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset11, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset12,
		sizeof (pfm_data) - reg_offset12,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset12, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset13,
		sizeof (pfm_data) - reg_offset13,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset13, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset21,
		sizeof (pfm_data) - reg_offset21,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset21, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset22,
		sizeof (pfm_data) - reg_offset22,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset22, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset3,
		sizeof (pfm_data) - img_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset3, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset3,
		sizeof (pfm_data) - sig_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset31,
		sizeof (pfm_data) - reg_offset31,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset31, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset32,
		sizeof (pfm_data) - reg_offset32,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset32, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset33,
		sizeof (pfm_data) - reg_offset33,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset33, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset34,
		sizeof (pfm_data) - reg_offset34,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset34, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset1,
		sizeof (pfm_data) - pub_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset1, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset1,
		sizeof (pfm_data) - key_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset1, 0, -1, 32));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset2,
		sizeof (pfm_data) - pub_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset2, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset2,
		sizeof (pfm_data) - key_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset3,
		sizeof (pfm_data) - pub_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset3, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset3,
		sizeof (pfm_data) - key_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 3, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, 32, img_list.images[0].key.mod_length);
	CuAssertIntEquals (test, 32, img_list.images[0].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[0].key.modulus[0]);
	CuAssertIntEquals (test, 11, img_list.images[0].signature[0]);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].length);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[1].start_addr);
	CuAssertIntEquals (test, 0x800000, img_list.images[0].regions[1].length);
	CuAssertIntEquals (test, 0x4000000, img_list.images[0].regions[2].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[0].regions[2].length);

	CuAssertIntEquals (test, 2, img_list.images[1].count);
	CuAssertPtrNotNull (test, img_list.images[1].regions);
	CuAssertIntEquals (test, 1, img_list.images[1].always_validate);
	CuAssertIntEquals (test, 3, img_list.images[1].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].sig_length);
	CuAssertIntEquals (test, 2, img_list.images[1].key.modulus[0]);
	CuAssertIntEquals (test, 22, img_list.images[1].signature[0]);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].length);
	CuAssertIntEquals (test, 0x50000, img_list.images[1].regions[1].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[1].length);

	CuAssertIntEquals (test, 4, img_list.images[2].count);
	CuAssertPtrNotNull (test, img_list.images[2].regions);
	CuAssertIntEquals (test, 0, img_list.images[2].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[2].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].sig_length);
	CuAssertIntEquals (test, 3, img_list.images[2].key.modulus[0]);
	CuAssertIntEquals (test, 33, img_list.images[2].signature[0]);
	CuAssertIntEquals (test, 0x6000000, img_list.images[2].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[2].regions[0].length);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[1].start_addr);
	CuAssertIntEquals (test, 0x200000, img_list.images[2].regions[1].length);
	CuAssertIntEquals (test, 0x40000, img_list.images[2].regions[2].start_addr);
	CuAssertIntEquals (test, 0x10000, img_list.images[2].regions[2].length);
	CuAssertIntEquals (test, 0x100000, img_list.images[2].regions[3].start_addr);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[3].length);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_unused_key (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE  +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_IMG_KEY_SIZE * 6) + (PFM_REGION_SIZE * 3 * 3) +
		PFM_MANIFEST_HEADER_SIZE + (PFM_KEY_HEADER_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset11 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int reg_offset12 = reg_offset11 + PFM_REGION_SIZE;
	int reg_offset13 = reg_offset12 + PFM_REGION_SIZE;
	int img_offset2 = reg_offset13 + PFM_REGION_SIZE;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset21 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int reg_offset22 = reg_offset21 + PFM_REGION_SIZE;
	int img_offset3 = reg_offset22 + PFM_REGION_SIZE;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset31 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int reg_offset32 = reg_offset31 + PFM_REGION_SIZE;
	int reg_offset33 = reg_offset32 + PFM_REGION_SIZE;
	int reg_offset34 = reg_offset33 + PFM_REGION_SIZE;
	int man_offset = reg_offset34 + PFM_REGION_SIZE;
	int pub_offset1 = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset1 = pub_offset1 + PFM_KEY_HEADER_SIZE;
	int pub_offset2 = key_offset1 + PFM_IMG_KEY_SIZE;
	int key_offset2 = pub_offset2 + PFM_KEY_HEADER_SIZE;
	int pub_offset3 = key_offset2 + PFM_IMG_KEY_SIZE;
	int key_offset3 = pub_offset3 + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 +
		((PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3)) * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 3;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset11];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset12];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset13];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 2);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 1;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 2;
	pfm_data[sig_offset2] = 22;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset21];
	region->start_addr = 0x20000;
	region->end_addr = 0x3ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset22];
	region->start_addr = 0x50000;
	region->end_addr = 0x6ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 4);
	img_header->flags = 0;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 4;
	pfm_data[sig_offset3] = 33;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset31];
	region->start_addr = 0x6000000;
	region->end_addr = 0x6ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset32];
	region->start_addr = 0x500000;
	region->end_addr = 0x6fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset33];
	region->start_addr = 0x40000;
	region->end_addr = 0x4ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset34];
	region->start_addr = 0x100000;
	region->end_addr = 0x5fffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE +
		((PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE) * 3);
	manifest_header->key_count = 3;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset1];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset1] = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset2];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 1;
	pfm_data[key_offset2] = 2;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset3];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 2;
	pfm_data[key_offset3] = 3;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset11,
		sizeof (pfm_data) - reg_offset11,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset11, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset12,
		sizeof (pfm_data) - reg_offset12,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset12, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset13,
		sizeof (pfm_data) - reg_offset13,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset13, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset21,
		sizeof (pfm_data) - reg_offset21,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset21, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset22,
		sizeof (pfm_data) - reg_offset22,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset22, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset3,
		sizeof (pfm_data) - img_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset3, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset3,
		sizeof (pfm_data) - sig_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset31,
		sizeof (pfm_data) - reg_offset31,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset31, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset32,
		sizeof (pfm_data) - reg_offset32,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset32, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset33,
		sizeof (pfm_data) - reg_offset33,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset33, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset34,
		sizeof (pfm_data) - reg_offset34,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset34, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset1,
		sizeof (pfm_data) - pub_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset1, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset1,
		sizeof (pfm_data) - key_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset2,
		sizeof (pfm_data) - pub_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset2, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset2,
		sizeof (pfm_data) - key_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, img_list.count);
	CuAssertPtrNotNull (test, img_list.images);

	CuAssertIntEquals (test, 3, img_list.images[0].count);
	CuAssertPtrNotNull (test, img_list.images[0].regions);
	CuAssertIntEquals (test, 1, img_list.images[0].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[0].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[0].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[0].key.modulus[0]);
	CuAssertIntEquals (test, 11, img_list.images[0].signature[0]);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[0].regions[0].length);
	CuAssertIntEquals (test, 0x2000000, img_list.images[0].regions[1].start_addr);
	CuAssertIntEquals (test, 0x800000, img_list.images[0].regions[1].length);
	CuAssertIntEquals (test, 0x4000000, img_list.images[0].regions[2].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[0].regions[2].length);

	CuAssertIntEquals (test, 2, img_list.images[1].count);
	CuAssertPtrNotNull (test, img_list.images[1].regions);
	CuAssertIntEquals (test, 1, img_list.images[1].always_validate);
	CuAssertIntEquals (test, 3, img_list.images[1].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[1].sig_length);
	CuAssertIntEquals (test, 2, img_list.images[1].key.modulus[0]);
	CuAssertIntEquals (test, 22, img_list.images[1].signature[0]);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[0].length);
	CuAssertIntEquals (test, 0x50000, img_list.images[1].regions[1].start_addr);
	CuAssertIntEquals (test, 0x20000, img_list.images[1].regions[1].length);

	CuAssertIntEquals (test, 4, img_list.images[2].count);
	CuAssertPtrNotNull (test, img_list.images[2].regions);
	CuAssertIntEquals (test, 0, img_list.images[2].always_validate);
	CuAssertIntEquals (test, 65537, img_list.images[2].key.exponent);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].key.mod_length);
	CuAssertIntEquals (test, PFM_IMG_KEY_SIZE, img_list.images[2].sig_length);
	CuAssertIntEquals (test, 1, img_list.images[2].key.modulus[0]);
	CuAssertIntEquals (test, 33, img_list.images[2].signature[0]);
	CuAssertIntEquals (test, 0x6000000, img_list.images[2].regions[0].start_addr);
	CuAssertIntEquals (test, 0x1000000, img_list.images[2].regions[0].length);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[1].start_addr);
	CuAssertIntEquals (test, 0x200000, img_list.images[2].regions[1].length);
	CuAssertIntEquals (test, 0x40000, img_list.images[2].regions[2].start_addr);
	CuAssertIntEquals (test, 0x10000, img_list.images[2].regions[2].length);
	CuAssertIntEquals (test, 0x100000, img_list.images[2].regions[3].start_addr);
	CuAssertIntEquals (test, 0x500000, img_list.images[2].regions[3].length);

	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_no_matching_key (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE  +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_IMG_KEY_SIZE * 6) + (PFM_REGION_SIZE * 3 * 3) +
		PFM_MANIFEST_HEADER_SIZE + (PFM_KEY_HEADER_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset11 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int reg_offset12 = reg_offset11 + PFM_REGION_SIZE;
	int reg_offset13 = reg_offset12 + PFM_REGION_SIZE;
	int img_offset2 = reg_offset13 + PFM_REGION_SIZE;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset21 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int reg_offset22 = reg_offset21 + PFM_REGION_SIZE;
	int img_offset3 = reg_offset22 + PFM_REGION_SIZE;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset31 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int reg_offset32 = reg_offset31 + PFM_REGION_SIZE;
	int reg_offset33 = reg_offset32 + PFM_REGION_SIZE;
	int reg_offset34 = reg_offset33 + PFM_REGION_SIZE;
	int man_offset = reg_offset34 + PFM_REGION_SIZE;
	int pub_offset1 = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset1 = pub_offset1 + PFM_KEY_HEADER_SIZE;
	int pub_offset2 = key_offset1 + PFM_IMG_KEY_SIZE;
	int key_offset2 = pub_offset2 + PFM_KEY_HEADER_SIZE;
	int pub_offset3 = key_offset2 + PFM_IMG_KEY_SIZE;
	int key_offset3 = pub_offset3 + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 +
		((PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3)) * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 3;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset11];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset12];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset13];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 2);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 1;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 2;
	pfm_data[sig_offset2] = 22;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset21];
	region->start_addr = 0x20000;
	region->end_addr = 0x3ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset22];
	region->start_addr = 0x50000;
	region->end_addr = 0x6ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 4);
	img_header->flags = 0;
	img_header->key_id = 3;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 4;
	pfm_data[sig_offset3] = 33;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset31];
	region->start_addr = 0x6000000;
	region->end_addr = 0x6ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset32];
	region->start_addr = 0x500000;
	region->end_addr = 0x6fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset33];
	region->start_addr = 0x40000;
	region->end_addr = 0x4ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset34];
	region->start_addr = 0x100000;
	region->end_addr = 0x5fffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE +
		((PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE) * 3);
	manifest_header->key_count = 3;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset1];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset1] = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset2];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 1;
	pfm_data[key_offset2] = 2;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset3];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 2;
	pfm_data[key_offset3] = 3;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset11,
		sizeof (pfm_data) - reg_offset11,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset11, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset12,
		sizeof (pfm_data) - reg_offset12,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset12, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset13,
		sizeof (pfm_data) - reg_offset13,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset13, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset21,
		sizeof (pfm_data) - reg_offset21,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset21, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset22,
		sizeof (pfm_data) - reg_offset22,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset22, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset3,
		sizeof (pfm_data) - img_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset3, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset3,
		sizeof (pfm_data) - sig_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset31,
		sizeof (pfm_data) - reg_offset31,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset31, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset32,
		sizeof (pfm_data) - reg_offset32,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset32, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset33,
		sizeof (pfm_data) - reg_offset33,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset33, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset34,
		sizeof (pfm_data) - reg_offset34,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset34, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset1,
		sizeof (pfm_data) - pub_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset1, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset1,
		sizeof (pfm_data) - key_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset2,
		sizeof (pfm_data) - pub_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset2, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset2,
		sizeof (pfm_data) - key_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset3,
		sizeof (pfm_data) - pub_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset3, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset3,
		sizeof (pfm_data) - key_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_KEY_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_empty_manifest (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (NULL, "Testing", &img_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_firmware_images (&pfm.base, NULL, &img_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_firmware_images (&pfm.base, "", &img_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_allowable_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_img_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_signature_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_region_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_manifest_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_REGION_OFFSET,
		PFM_DATA_LEN - PFM_IMG_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_key_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_FW_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_FW_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_FW_HEADER_OFFSET, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_VERSION_OFFSET,
		PFM_DATA_LEN - PFM_VERSION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_VERSION_OFFSET, 0, -1, strlen (PFM_VERSION_ID)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_HEADER_OFFSET,
		PFM_DATA_LEN - PFM_IMG_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_HEADER_OFFSET, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_IMG_SIGNATURE, PFM_IMG_KEY_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_SIG_OFFSET, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_IMG_REGION_OFFSET,
		PFM_DATA_LEN - PFM_IMG_REGION_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_IMG_REGION_OFFSET, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_key_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	const char *version1 = "V1";
	uint8_t pfm_data[PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE + PFM_FW_HEADER_SIZE  +
		(PFM_IMG_HEADER_SIZE * 3) + (PFM_IMG_KEY_SIZE * 6) + (PFM_REGION_SIZE * 3 * 3) +
		PFM_MANIFEST_HEADER_SIZE + (PFM_KEY_HEADER_SIZE * 3) + 4];
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset11 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int reg_offset12 = reg_offset11 + PFM_REGION_SIZE;
	int reg_offset13 = reg_offset12 + PFM_REGION_SIZE;
	int img_offset2 = reg_offset13 + PFM_REGION_SIZE;
	int sig_offset2 = img_offset2 + PFM_IMG_HEADER_SIZE;
	int reg_offset21 = sig_offset2 + PFM_IMG_KEY_SIZE;
	int reg_offset22 = reg_offset21 + PFM_REGION_SIZE;
	int img_offset3 = reg_offset22 + PFM_REGION_SIZE;
	int sig_offset3 = img_offset3 + PFM_IMG_HEADER_SIZE;
	int reg_offset31 = sig_offset3 + PFM_IMG_KEY_SIZE;
	int reg_offset32 = reg_offset31 + PFM_REGION_SIZE;
	int reg_offset33 = reg_offset32 + PFM_REGION_SIZE;
	int reg_offset34 = reg_offset33 + PFM_REGION_SIZE;
	int man_offset = reg_offset34 + PFM_REGION_SIZE;
	int pub_offset1 = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset1 = pub_offset1 + PFM_KEY_HEADER_SIZE;
	int pub_offset2 = key_offset1 + PFM_IMG_KEY_SIZE;
	int key_offset2 = pub_offset2 + PFM_KEY_HEADER_SIZE;
	int pub_offset3 = key_offset2 + PFM_IMG_KEY_SIZE;
	int key_offset3 = pub_offset3 + PFM_KEY_HEADER_SIZE;

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 1;

	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 +
		((PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3)) * 3);
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 3;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 3);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 3;
	pfm_data[sig_offset1] = 11;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset11];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset12];
	region->start_addr = 0x2000000;
	region->end_addr = 0x27fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset13];
	region->start_addr = 0x4000000;
	region->end_addr = 0x401ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset2];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 2);
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 1;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 2;
	pfm_data[sig_offset2] = 22;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset21];
	region->start_addr = 0x20000;
	region->end_addr = 0x3ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset22];
	region->start_addr = 0x50000;
	region->end_addr = 0x6ffff;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset3];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + (PFM_REGION_SIZE * 4);
	img_header->flags = 0;
	img_header->key_id = 2;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 4;
	pfm_data[sig_offset3] = 33;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset31];
	region->start_addr = 0x6000000;
	region->end_addr = 0x6ffffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset32];
	region->start_addr = 0x500000;
	region->end_addr = 0x6fffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset33];
	region->start_addr = 0x40000;
	region->end_addr = 0x4ffff;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset34];
	region->start_addr = 0x100000;
	region->end_addr = 0x5fffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE +
		((PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE) * 3);
	manifest_header->key_count = 3;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset1];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 0;
	pfm_data[key_offset1] = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset2];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 1;
	pfm_data[key_offset2] = 2;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset3];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 65537;
	key_header->id = 2;
	pfm_data[key_offset3] = 3;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + PFM_HEADER_SIZE,
		sizeof (pfm_data) - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + ver_offset1,
		sizeof (pfm_data) - ver_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1, 0, -1, PFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		pfm_data + ver_offset1 + PFM_FW_HEADER_SIZE,
		sizeof (pfm_data) - ver_offset1 - PFM_FW_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + ver_offset1 + PFM_FW_HEADER_SIZE, 0, -1,
			strlen (version1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset1,
		sizeof (pfm_data) - img_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset1, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset1,
		sizeof (pfm_data) - sig_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset11,
		sizeof (pfm_data) - reg_offset11,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset11, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset12,
		sizeof (pfm_data) - reg_offset12,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset12, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset13,
		sizeof (pfm_data) - reg_offset13,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset13, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset2,
		sizeof (pfm_data) - img_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset2, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset2,
		sizeof (pfm_data) - sig_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset2, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset21,
		sizeof (pfm_data) - reg_offset21,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset21, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset22,
		sizeof (pfm_data) - reg_offset22,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset22, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + img_offset3,
		sizeof (pfm_data) - img_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + img_offset3, 0, -1, PFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + sig_offset3,
		sizeof (pfm_data) - sig_offset3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset3, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset31,
		sizeof (pfm_data) - reg_offset31,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset31, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset32,
		sizeof (pfm_data) - reg_offset32,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset32, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset33,
		sizeof (pfm_data) - reg_offset33,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset33, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + reg_offset34,
		sizeof (pfm_data) - reg_offset34,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + reg_offset34, 0, -1, PFM_REGION_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + man_offset,
		sizeof (pfm_data) - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset1,
		sizeof (pfm_data) - pub_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset1, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + key_offset1,
		sizeof (pfm_data) - key_offset1,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + key_offset1, 0, -1, PFM_IMG_KEY_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data + pub_offset2,
		sizeof (pfm_data) - pub_offset2,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pub_offset2, 0, -1, PFM_KEY_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, version1, &img_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_firmware_images_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_firmware_images (&pfm.base, "Testing", &img_list);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_free_firmware_images_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	pfm.base.free_firmware_images (&pfm.base, NULL);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_free_firmware_images_null_list (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	img_list.count = 1;
	img_list.images = NULL;
	pfm.base.free_firmware_images (&pfm.base, &img_list);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		PFM_DATA + PFM_PLATFORM_HEADER_OFFSET, PFM_DATA_LEN - PFM_PLATFORM_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_PLATFORM_HEADER_OFFSET, 0, -1,
			PFM_PLATFORM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_PLATFORM_ID_OFFSET,
		PFM_DATA_LEN - PFM_PLATFORM_ID_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_PLATFORM_ID_OFFSET, 0, -1,
			strlen (PFM_PLATFORM_ID)));

	CuAssertIntEquals (test, 0, status);

	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, PFM_PLATFORM_ID, id);

	platform_free (id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (NULL, &id);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, id);

	status = pfm.base.get_platform_id (&pfm.base, NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_allowable_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_manifest_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_platform_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_identifier_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_ALLOWED_HDR_OFFSET,
		PFM_DATA_LEN - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA + PFM_MANIFEST_OFFSET,
		PFM_DATA_LEN - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		PFM_DATA + PFM_PLATFORM_HEADER_OFFSET, PFM_DATA_LEN - PFM_PLATFORM_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_PLATFORM_HEADER_OFFSET, 0, -1,
			PFM_PLATFORM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}

static void pfm_flash_test_get_platform_id_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pfm_flash pfm;
	int status;
	char *id;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pfm.base.get_platform_id (&pfm.base, &id);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_release (&pfm);

	spi_flash_release (&flash);
}


CuSuite* get_pfm_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pfm_flash_test_init);
	SUITE_ADD_TEST (suite, pfm_flash_test_init_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_init_not_block_aligned);
	SUITE_ADD_TEST (suite, pfm_flash_test_release_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_release_no_init);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_addr_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_flash_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_bad_magic_number);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_allowable_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_manifest_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_platform_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_missing_platform_id);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_header_reserved_non_zero);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_allowable_header_reserved_non_zero);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_manifest_header_reserved_non_zero);
	SUITE_ADD_TEST (suite, pfm_flash_test_verify_platform_header_reserved_non_zero);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_id);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_id_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_id_bad_magic_num);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_hash);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_hash_after_verify);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_hash_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_hash_bad_magic_num);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_signature);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_signature_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_signature_bad_magic_number);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_multiple);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_allowable_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_fw_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_id_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_supported_versions_bad_magic_num);
	SUITE_ADD_TEST (suite, pfm_flash_test_free_fw_versions_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_free_fw_versions_null_list);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_wrong_version);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_version_diff_len);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_multiple_versions);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_multiple_regions);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_allowable_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_fw_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_version_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_region_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_read_write_regions_bad_magic_num);
	SUITE_ADD_TEST (suite, pfm_flash_test_free_read_write_regions_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_no_flags);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_unknown_flags);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_no_version_padding);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_unknown_version);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_multiple_versions);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_multiple_regions);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_multiple_images);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_multiple_keys);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_key_id_matches_length);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_unused_key);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_no_matching_key);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_allowable_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_img_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_signature_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_region_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_manifest_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_key_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_key_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_firmware_images_bad_magic_num);
	SUITE_ADD_TEST (suite, pfm_flash_test_free_firmware_images_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_free_firmware_images_null_list);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_null);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_allowable_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_manifest_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_platform_header_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_identifier_read_error);
	SUITE_ADD_TEST (suite, pfm_flash_test_get_platform_id_bad_magic_num);

	return suite;
}
