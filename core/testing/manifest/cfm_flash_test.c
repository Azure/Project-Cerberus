// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/cfm/cfm_flash.h"
#include "manifest/cfm/cfm_format.h"
#include "flash/spi_flash.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/cfm_testing.h"


TEST_SUITE_LABEL ("cfm_flash");


/**
 * Dummy CFM for testing.
 */
const uint8_t CFM_DATA[] = {
	0x98,0x01,0x92,0xa5,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x8c,0x00,0x02,0x00,
	0x44,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x3c,0x00,0x01,0x00,0x09,0x00,0x00,0x00,
	0x76,0x30,0x32,0x2e,0x30,0x32,0x2e,0x30,0x32,0x00,0x00,0x00,0x28,0x00,0x20,0x00,
	0x03,0x00,0x00,0x00,0x85,0x08,0xf3,0x46,0xb4,0xda,0x1f,0xec,0x3e,0x78,0x20,0xc1,
	0x58,0x2f,0x73,0xe2,0x1c,0x18,0xa2,0x83,0x5d,0xc0,0x99,0x26,0x0b,0xb9,0xaf,0x13,
	0x65,0x03,0xee,0x2d,0x44,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x01,0x00,
	0x09,0x00,0x00,0x00,0x76,0x30,0x31,0x2e,0x30,0x31,0x2e,0x30,0x31,0x00,0x00,0x00,
	0x28,0x00,0x20,0x00,0x02,0x00,0x00,0x00,0x85,0x08,0xf3,0x46,0xb4,0xda,0x1f,0xec,
	0x3e,0x78,0x20,0xc1,0x58,0x2f,0x73,0xe2,0x1c,0x18,0xa2,0x83,0x5d,0xc0,0x99,0x26,
	0x0b,0xb9,0xaf,0x13,0x65,0x03,0xee,0x2d,0xb2,0x1f,0xc9,0x41,0x36,0x9a,0x84,0x92,
	0x20,0x52,0x73,0x60,0xa8,0x92,0xae,0x7e,0x92,0x12,0xde,0xc9,0x20,0x7e,0x00,0x92,
	0x16,0xe2,0x94,0x88,0x9c,0x10,0xf7,0x22,0xbf,0xf3,0xe9,0x83,0xaf,0x84,0xaf,0x8a,
	0xda,0x3f,0xd2,0x26,0x7f,0x81,0xb0,0xa7,0xc3,0xb3,0x0c,0x03,0x50,0xbb,0x8a,0xdf,
	0x7b,0x3c,0x29,0xb6,0x6e,0x75,0x89,0xc7,0x8e,0xba,0xe3,0x37,0x10,0x2c,0x3b,0xba,
	0x21,0x27,0x45,0x8d,0x1b,0x26,0x44,0xbc,0xc1,0xe7,0x99,0x75,0xa9,0x9c,0xef,0xdf,
	0x1a,0x86,0x8a,0x89,0x4a,0xf7,0x4a,0x90,0x04,0x06,0xae,0x58,0xdc,0x2d,0x42,0x2c,
	0x81,0xcf,0xd2,0x77,0x70,0xfb,0x2a,0x09,0x33,0xce,0x60,0xb4,0x7a,0x3e,0x9c,0x25,
	0x0d,0xcd,0x6d,0xa5,0xb7,0x3d,0x21,0xf8,0x5a,0x65,0x74,0x05,0x72,0x9b,0x50,0x07,
	0xbe,0xd8,0x18,0xf4,0x94,0xd0,0x22,0x06,0xf1,0xd7,0xe6,0x0b,0x9c,0xd5,0x76,0x5d,
	0xb8,0x5f,0xb3,0xae,0x35,0x14,0x6d,0x86,0x3b,0x26,0x37,0x5d,0xd7,0x4a,0x5b,0x62,
	0x5d,0x2d,0x46,0x4b,0xc0,0xb1,0xde,0x79,0x90,0x58,0x78,0x52,0xc4,0xbf,0x34,0x45,
	0x1f,0x49,0x9f,0x6d,0xfa,0x8d,0xf1,0x47,0xce,0x69,0x26,0xfb,0x0a,0x5f,0x03,0xd3,
	0x28,0xdf,0x96,0x2f,0xff,0xfa,0x8a,0x4a,0x91,0x17,0xed,0xc6,0xb8,0xc9,0xba,0xe3,
	0xce,0x21,0xb8,0x5b,0x33,0x82,0xef,0x36,0xfd,0xa7,0x26,0x6e,0xf7,0x97,0x65,0x44,
	0xf6,0x52,0x49,0x50,0x81,0x6d,0xa6,0x0b,0xf7,0xf5,0x53,0x9b,0x43,0x45,0x5f,0xa7,
	0x2c,0x09,0xc6,0xde,0xb1,0x42,0x87,0xe3
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_DATA_LEN = sizeof (CFM_DATA);

/**
 * CFM_DATA hash for testing.
 */
const uint8_t CFM_HASH[] = {
	0xbf,0xff,0xa2,0x24,0x9e,0x15,0x1f,0x4f,0xba,0x2a,0x3b,0x57,0x69,0x8b,0xf7,0x43,
	0x0f,0xa4,0xeb,0xb4,0xdf,0x50,0x5a,0xed,0x89,0xcb,0xee,0xb1,0x07,0xb4,0x90,0x86
};

/**
 * CFM_DATA hash digest for testing.
 */
const uint8_t CFM_HASH_DIGEST[] = {
	0x69,0x8e,0x6a,0xbd,0x62,0xdd,0xa6,0x16,0x2e,0xaf,0x15,0xc6,0x0a,0x69,0xbe,0x6e,
	0x3f,0xb9,0xbc,0xad,0xbf,0x61,0xd1,0xba,0xb9,0x9a,0xc1,0x07,0x8d,0x6d,0xab,0x02
};

/**
 * Length of the test CFM hash.
 */
const uint32_t CFM_HASH_LEN = sizeof (CFM_HASH);

/* Test CFM components. */

/**
* The signed image digest in the CFM data.
*/
const uint8_t TEST_DIGEST[] = {
	0x85,0x08,0xf3,0x46,0xb4,0xda,0x1f,0xec,0x3e,0x78,0x20,0xc1,0x58,0x2f,0x73,0xe2,
	0x1c,0x18,0xa2,0x83,0x5d,0xc0,0x99,0x26,0x0b,0xb9,0xaf,0x13,0x65,0x03,0xee,0x2d
};

/**
* The FW version identifier in the CFM data.
*/
const char TEST_VERSION_ID_1[] = "v01.01.01";

/**
* The FW version identifier in the CFM data.
*/
const char TEST_VERSION_ID_2[] = "v02.02.02";

/*
 * The platform identifier in the CFM data
 */
const char CFM_PLATFORM_ID[] = "CFM_Test1";

/*
 * Length of CFM platform ID
 */
const size_t CFM_PLATFORM_ID_LEN = sizeof (CFM_PLATFORM_ID) - 1;

/**
 * The length of the CFM signature.
 */
const size_t CFM_SIGNATURE_LEN = 256;

/**
 * The offset from the base for the CFM signature.
 */
const uint32_t CFM_SIGNATURE_OFFSET = (sizeof (CFM_DATA) - 256);

/**
 * The signature for the CFM.
 */
const uint8_t *CFM_SIGNATURE = CFM_DATA + (sizeof (CFM_DATA) - 256);

/**
 * The address offset for the allow versions header.
 */
#define	CFM_COMPONENTS_HDR_OFFSET	(CFM_HEADER_SIZE)

/**
 * The offset of the first component header in the CFM.
 */
#define	CFM_2ND_COMPONENT_HDR_OFFSET	(CFM_COMPONENTS_HDR_OFFSET + CFM_COMPONENTS_HDR_SIZE)

/**
 * The offset of the first component firmware header in the CFM.
 */
#define	CFM_2ND_COMPONENT_FW_HDR_OFFSET	(CFM_2ND_COMPONENT_HDR_OFFSET + CFM_COMPONENT_HDR_SIZE)

/**
 * The offset of the first component firmware version ID in the CFM.
 */
#define	CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET	(CFM_2ND_COMPONENT_FW_HDR_OFFSET + CFM_FW_HEADER_SIZE)

/**
 * The offset of the first component signed image header in the CFM.
 */
#define	CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET	(CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET + 12)

/**
 * The offset of the first component signed image digest in the CFM.
 */
#define	CFM_2ND_COMPONENT_SIGNED_IMG_DIGEST_OFFSET	(CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET + CFM_IMG_HEADER_SIZE)

/**
 * The offset of the second component header in the CFM.
 */
#define	CFM_1ST_COMPONENT_HDR_OFFSET	(CFM_2ND_COMPONENT_HDR_OFFSET + 68)

/**
 * The offset of the first component firmware header in the CFM.
 */
#define	CFM_1ST_COMPONENT_FW_HDR_OFFSET	(CFM_1ST_COMPONENT_HDR_OFFSET + CFM_COMPONENT_HDR_SIZE)

/**
 * The offset of the first component firmware version ID in the CFM.
 */
#define	CFM_1ST_COMPONENT_FW_VERSION_ID_OFFSET	(CFM_1ST_COMPONENT_FW_HDR_OFFSET + CFM_FW_HEADER_SIZE)

/**
 * The offset of the first component signed image header in the CFM.
 */
#define	CFM_1ST_COMPONENT_SIGNED_IMG_HDR_OFFSET	(CFM_1ST_COMPONENT_FW_VERSION_ID_OFFSET + 12)

/**
 * The offset of the first component signed image digest in the CFM.
 */
#define	CFM_1ST_COMPONENT_SIGNED_IMG_DIGEST_OFFSET	(CFM_1ST_COMPONENT_SIGNED_IMG_HDR_OFFSET + CFM_IMG_HEADER_SIZE)


/**
 * Dependencies for testing CFMs.
 */
struct cfm_flash_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< CFM signature verification. */
	struct flash_master_mock flash_mock;				/**< Flash master for the CFM flash. */
	struct spi_flash flash;								/**< Flash where the CFM is stored. */
	uint32_t addr;										/**< Base address of the CFM. */
	uint8_t signature[256];								/**< Buffer for the manifest signature. */
	uint8_t platform_id[256];							/**< Cache for the platform ID. */
	struct cfm_flash test;								/**< CFM instance under test. */
};


/**
 * Initialize common CFM testing dependencies.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 */
static void cfm_flash_testing_init_dependencies (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&cfm->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&cfm->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&cfm->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&cfm->flash, &cfm->flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&cfm->flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	cfm->addr = address;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param cfm The testing components to release.
 */
void cfm_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct cfm_flash_testing *cfm)
{
	int status;

	status = flash_master_mock_validate_and_release (&cfm->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&cfm->verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&cfm->flash);
	HASH_TESTING_ENGINE_RELEASE (&cfm->hash);
}

/**
 * Initialize CFM for testing.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 */
static void cfm_flash_testing_init (CuTest *test, struct cfm_flash_testing *cfm, uint32_t address)
{
	int status;

	cfm_flash_testing_init_dependencies (test, cfm, address);

	status = cfm_flash_init (&cfm->test, &cfm->flash.base, address, cfm->signature,
		sizeof (cfm->signature), cfm->platform_id, sizeof (cfm->platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cfm->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cfm->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param cfm The testing components to release.
 */
static void cfm_flash_testing_validate_and_release (CuTest *test, struct cfm_flash_testing *cfm)
{
	cfm_flash_release (&cfm->test);

	cfm_flash_testing_validate_and_release_dependencies (test, cfm);
}

/**
 * Set up expectations for verifying a CFM on flash.
 *
 * @param test The testing framework.
 * @param cfm The testing components.
 * @param data The CFM data to read.
 * @param length The length of the CFM data.
 * @param hash The CFM hash.  Null to skip hash checking.
 * @param signature The CFM signature.
 * @param sig_offset Offset of the CFM signature.
 * @param sig_result Result of the signature verification call.
 */
static void cfm_flash_testing_verify_cfm (CuTest *test, struct cfm_flash_testing *cfm,
	const uint8_t *data, size_t length, const uint8_t *hash, const uint8_t *signature,
	uint32_t sig_offset, int sig_result)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (&cfm->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm->flash_mock, 0, data, CFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, cfm->addr, 0, -1, CFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&cfm->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm->flash_mock, 0, signature, CFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, cfm->addr + sig_offset, 0, -1, CFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&cfm->flash_mock, cfm->addr, data,
		length - CFM_SIGNATURE_LEN);

	if (hash) {
		status |= mock_expect (&cfm->verification.mock, cfm->verification.base.verify_signature,
			&cfm->verification, sig_result, MOCK_ARG_PTR_CONTAINS (hash, CFM_HASH_LEN),
			MOCK_ARG (CFM_HASH_LEN), MOCK_ARG_PTR_CONTAINS (signature, CFM_SIGNATURE_LEN),
			MOCK_ARG (CFM_SIGNATURE_LEN));
	}
	else {
		status |= mock_expect (&cfm->verification.mock, cfm->verification.base.verify_signature,
			&cfm->verification, sig_result, MOCK_ARG_NOT_NULL, MOCK_ARG (CFM_HASH_LEN),
			MOCK_ARG_PTR_CONTAINS (signature, CFM_SIGNATURE_LEN), MOCK_ARG (CFM_SIGNATURE_LEN));
	}

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a CFM for testing.  Run verification to load the CFM information.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 * @param data The CFM data to read.
 * @param length The length of the CFM data.
 * @param hash The CFM hash.
 * @param signature The CFM signature.
 * @param sig_offset Offset of the CFM signature.
 * @param sig_result Result of the signature verification call.
 */
static void cfm_flash_testing_init_and_verify (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address, const uint8_t *data, size_t length, const uint8_t *hash,
	const uint8_t *signature, uint32_t sig_offset, int sig_result)
{
	int status;

	cfm_flash_testing_init (test, cfm, address);
	cfm_flash_testing_verify_cfm (test, cfm, data, length, hash, signature, sig_offset, sig_result);

	status = cfm->test.base.base.verify (&cfm->test.base.base, &cfm->hash.base,
		&cfm->verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&cfm->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cfm->verification.mock);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void cfm_flash_test_init (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_dependencies (test, &cfm, 0x10000);

	status = cfm_flash_init (&cfm.test, &cfm.flash.base, 0x10000, cfm.signature,
		sizeof (cfm.signature), cfm.platform_id, sizeof (cfm.platform_id));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cfm.test.base.base.verify);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_id);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_platform_id);
	CuAssertPtrNotNull (test, cfm.test.base.base.free_platform_id);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_hash);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_signature);
	CuAssertPtrNotNull (test, cfm.test.base.base.is_empty);

	CuAssertPtrNotNull (test, cfm.test.base.get_supported_component_ids);
	CuAssertPtrNotNull (test, cfm.test.base.free_component_ids);
	CuAssertPtrNotNull (test, cfm.test.base.get_component);
	CuAssertPtrNotNull (test, cfm.test.base.free_component);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&cfm.test.base_flash));
	CuAssertPtrEquals (test, &cfm.flash, manifest_flash_get_flash (&cfm.test.base_flash));

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_init_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_dependencies (test, &cfm, 0x10000);

	status = cfm_flash_init (NULL, &cfm.flash.base, 0x10000, cfm.signature,
		sizeof (cfm.signature), cfm.platform_id, sizeof (cfm.platform_id));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm_flash_init (&cfm.test, NULL, 0x10000, cfm.signature,
		sizeof (cfm.signature), cfm.platform_id, sizeof (cfm.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = cfm_flash_init (&cfm.test, &cfm.flash.base, 0x10000, NULL,
		sizeof (cfm.signature), cfm.platform_id, sizeof (cfm.platform_id));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm_flash_init (&cfm.test, &cfm.flash.base, 0x10000, cfm.signature,
		sizeof (cfm.signature), NULL, sizeof (cfm.platform_id));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release_dependencies (test, &cfm);
}

static void cfm_flash_test_init_not_block_aligned (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_dependencies (test, &cfm, 0x10000);

	status = cfm_flash_init (&cfm.test, &cfm.flash.base, 0x10001, cfm.signature,
		sizeof (cfm.signature), cfm.platform_id, sizeof (cfm.platform_id));
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	cfm_flash_testing_validate_and_release_dependencies (test, &cfm);
}

static void cfm_flash_test_release_null (CuTest *test)
{
	TEST_START;

	cfm_flash_release (NULL);
}

static void cfm_flash_test_verify (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_SIGNATURE,
		CFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_SIGNATURE_OFFSET, 0, -1, CFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&cfm.flash_mock, 0x10000, CFM_DATA,
		CFM_DATA_LEN - CFM_SIGNATURE_LEN);

	status |= mock_expect (&cfm.verification.mock, cfm.verification.base.verify_signature,
		&cfm.verification, 0, MOCK_ARG_PTR_CONTAINS (CFM_HASH, CFM_HASH_LEN),
		MOCK_ARG (CFM_HASH_LEN), MOCK_ARG_PTR_CONTAINS (CFM_SIGNATURE, CFM_SIGNATURE_LEN),
		MOCK_ARG (CFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.hash.base, &cfm.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.verify (NULL, &cfm.hash.base, &cfm.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.verify (&cfm.test.base.base, NULL, &cfm.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.hash.base, NULL,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_bad_magic_number (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint8_t cfm_bad_data[CFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (cfm_bad_data, CFM_DATA, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, cfm_bad_data,
		sizeof (cfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.hash.base, &cfm.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint32_t id;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_id (&cfm.test.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_id_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint32_t id;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_id (&cfm.test.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_id_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint32_t id;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_id (&cfm.test.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&cfm.flash_mock, 0x10000, CFM_DATA,
		CFM_DATA_LEN - CFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (CFM_HASH, hash_out, CFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash_after_verify (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (CFM_HASH, hash_out, CFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_hash (NULL, &cfm.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, NULL, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash_bad_magic_num (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t cfm_bad_data[CFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (cfm_bad_data, CFM_DATA, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, cfm_bad_data,
		sizeof (cfm_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[CFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_SIGNATURE,
		CFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_SIGNATURE_OFFSET, 0, -1, CFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, CFM_SIGNATURE_LEN, status);

	status = testing_validate_array (CFM_SIGNATURE, sig_out, CFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature_after_verify (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[CFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, CFM_SIGNATURE_LEN, status);

	status = testing_validate_array (CFM_SIGNATURE, sig_out, CFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t cfm_bad_data[CFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (cfm_bad_data, CFM_DATA, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, cfm_bad_data,
		sizeof (cfm_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_1ST_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_1ST_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_1ST_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, &ids);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, ids.count);
	CuAssertPtrNotNull (test, ids.ids);
	CuAssertIntEquals (test, 2, ids.ids[0]);
	CuAssertIntEquals (test, 1, ids.ids[1]);

	cfm.test.base.free_component_ids (&cfm.test.base, &ids);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.get_supported_component_ids (NULL, &ids);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, &ids);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids_manifest_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, &ids);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids_components_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, &ids);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids_component_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, &ids);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_supported_component_ids_bad_magic_number (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids;
	uint8_t cfm_bad_data[CFM_SIGNATURE_OFFSET];
	int status;

	TEST_START;

	memcpy (cfm_bad_data, CFM_DATA, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, cfm_bad_data,
		sizeof (cfm_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_supported_component_ids (&cfm.test.base, &ids);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_component_ids_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm.test.base.free_component_ids (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_component_ids_null_list (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component_ids ids;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	ids.count = 1;
	ids.ids = NULL;
	cfm.test.base.free_component_ids (&cfm.test.base, &ids);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_1st_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int i;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_1ST_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_1ST_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_1ST_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_1ST_COMPONENT_FW_HDR_OFFSET, CFM_DATA_LEN - CFM_1ST_COMPONENT_FW_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_1ST_COMPONENT_FW_HDR_OFFSET, 0, -1,
			CFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_1ST_COMPONENT_FW_VERSION_ID_OFFSET,
		CFM_DATA_LEN - CFM_1ST_COMPONENT_FW_VERSION_ID_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_1ST_COMPONENT_FW_VERSION_ID_OFFSET, 0, -1, 9));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_1ST_COMPONENT_SIGNED_IMG_HDR_OFFSET,
		CFM_DATA_LEN - CFM_1ST_COMPONENT_SIGNED_IMG_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_1ST_COMPONENT_SIGNED_IMG_HDR_OFFSET, 0, -1,
			CFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_1ST_COMPONENT_SIGNED_IMG_DIGEST_OFFSET,
		CFM_DATA_LEN - CFM_1ST_COMPONENT_SIGNED_IMG_DIGEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_1ST_COMPONENT_SIGNED_IMG_DIGEST_OFFSET, 0, -1,
			sizeof (TEST_DIGEST)));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 1, &component);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, component.component_id);
	CuAssertIntEquals (test, 1, component.fw_count);
	CuAssertPtrNotNull (test, component.fw);
	CuAssertIntEquals (test, 1, component.fw[0].img_count);
	CuAssertIntEquals (test, 9, component.fw[0].version_length);
	CuAssertPtrNotNull (test, component.fw[0].fw_version_id);
	CuAssertStrEquals (test, TEST_VERSION_ID_1, component.fw[0].fw_version_id);
	CuAssertPtrNotNull (test, component.fw[0].imgs);
	CuAssertIntEquals (test, 2, component.fw[0].imgs[0].failure_action);
	CuAssertIntEquals (test, 32, component.fw[0].imgs[0].digest_length);
	CuAssertPtrNotNull (test, component.fw[0].imgs[0].digest);

	for (i = 0; i < (int) sizeof (TEST_DIGEST); ++i) {
		CuAssertIntEquals (test, TEST_DIGEST[i], component.fw[0].imgs[0].digest[i]);
	}

	cfm.test.base.free_component (&cfm.test.base, &component);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_2nd_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int i;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_HDR_OFFSET, 0, -1,
			CFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET,
		CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET, 0, -1, 9));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET,
		CFM_DATA_LEN - CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET, 0, -1,
			CFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_SIGNED_IMG_DIGEST_OFFSET,
		CFM_DATA_LEN - CFM_2ND_COMPONENT_SIGNED_IMG_DIGEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_SIGNED_IMG_DIGEST_OFFSET, 0, -1,
			sizeof (TEST_DIGEST)));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, component.component_id);
	CuAssertIntEquals (test, 1, component.fw_count);
	CuAssertPtrNotNull (test, component.fw);
	CuAssertIntEquals (test, 1, component.fw[0].img_count);
	CuAssertIntEquals (test, 9, component.fw[0].version_length);
	CuAssertPtrNotNull (test, component.fw[0].fw_version_id);
	CuAssertStrEquals (test, TEST_VERSION_ID_2, component.fw[0].fw_version_id);
	CuAssertPtrNotNull (test, component.fw[0].imgs);
	CuAssertIntEquals (test, 3, component.fw[0].imgs[0].failure_action);
	CuAssertIntEquals (test, sizeof (TEST_DIGEST), component.fw[0].imgs[0].digest_length);
	CuAssertPtrNotNull (test, component.fw[0].imgs[0].digest);

	for (i = 0; i < (int) sizeof (TEST_DIGEST); ++i) {
		CuAssertIntEquals (test, TEST_DIGEST[i], component.fw[0].imgs[0].digest[i]);
	}

	cfm.test.base.free_component (&cfm.test.base, &component);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.get_component (NULL, 2, &component);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_manifest_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_components_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_component_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_fw_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));
	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_fw_version_id_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_HDR_OFFSET, 0, -1,
			CFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_img_header_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_HDR_OFFSET, 0, -1,
			CFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET,
		CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET, 0, -1, 9));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_img_digest_read_error (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component = {0};
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, CFM_DATA, CFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_COMPONENTS_HDR_OFFSET, CFM_DATA_LEN - CFM_COMPONENTS_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_COMPONENTS_HDR_OFFSET, 0, -1,
			CFM_COMPONENTS_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_HDR_OFFSET, 0, -1,
			CFM_COMPONENT_HDR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_HDR_OFFSET, CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_HDR_OFFSET, 0, -1,
			CFM_FW_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET,
		CFM_DATA_LEN - CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_FW_VERSION_ID_OFFSET, 0, -1, 9));

	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0,
		CFM_DATA + CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET,
		CFM_DATA_LEN - CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + CFM_2ND_COMPONENT_SIGNED_IMG_HDR_OFFSET, 0, -1,
			CFM_IMG_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&cfm.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_bad_magic_number (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_component component;
	uint8_t cfm_bad_data[CFM_SIGNATURE_OFFSET];
	int status;

	TEST_START;

	memcpy (cfm_bad_data, CFM_DATA, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&cfm.flash_mock, 0, cfm_bad_data,
		sizeof (cfm_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, CFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component (&cfm.test.base, 2, &component);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, id);
	CuAssertStrEquals (test, "", id);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id_manifest_allocation (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char *id = NULL;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, "", id);

	cfm.test.base.base.free_platform_id (&cfm.test.base.base, id);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char *id = NULL;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.get_platform_id (NULL, &id, 0);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, CFM_DATA, CFM_DATA_LEN, CFM_HASH,
		CFM_SIGNATURE, CFM_SIGNATURE_OFFSET, 0);

	status = cfm.test.base.base.is_empty (NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}


TEST_SUITE_START (cfm_flash);

TEST (cfm_flash_test_init);
TEST (cfm_flash_test_init_null);
TEST (cfm_flash_test_init_not_block_aligned);
TEST (cfm_flash_test_release_null);
TEST (cfm_flash_test_verify);
TEST (cfm_flash_test_verify_null);
TEST (cfm_flash_test_verify_bad_magic_number);
TEST (cfm_flash_test_get_id);
TEST (cfm_flash_test_get_id_null);
TEST (cfm_flash_test_get_id_verify_never_run);
TEST (cfm_flash_test_get_hash);
TEST (cfm_flash_test_get_hash_after_verify);
TEST (cfm_flash_test_get_hash_null);
TEST (cfm_flash_test_get_hash_bad_magic_num);
TEST (cfm_flash_test_get_signature);
TEST (cfm_flash_test_get_signature_after_verify);
TEST (cfm_flash_test_get_signature_null);
TEST (cfm_flash_test_get_signature_bad_magic_number);
TEST (cfm_flash_test_get_supported_component_ids);
TEST (cfm_flash_test_get_supported_component_ids_null);
TEST (cfm_flash_test_get_supported_component_ids_verify_never_run);
TEST (cfm_flash_test_get_supported_component_ids_manifest_header_read_error);
TEST (cfm_flash_test_get_supported_component_ids_components_header_read_error);
TEST (cfm_flash_test_get_supported_component_ids_component_header_read_error);
TEST (cfm_flash_test_get_supported_component_ids_bad_magic_number);
TEST (cfm_flash_test_free_component_ids_null);
TEST (cfm_flash_test_free_component_ids_null_list);
TEST (cfm_flash_test_get_1st_component);
TEST (cfm_flash_test_get_2nd_component);
TEST (cfm_flash_test_get_component_null);
TEST (cfm_flash_test_get_component_verify_never_run);
TEST (cfm_flash_test_get_component_manifest_header_read_error);
TEST (cfm_flash_test_get_component_components_header_read_error);
TEST (cfm_flash_test_get_component_component_header_read_error);
TEST (cfm_flash_test_get_component_fw_header_read_error);
TEST (cfm_flash_test_get_component_fw_version_id_read_error);
TEST (cfm_flash_test_get_component_img_header_read_error);
TEST (cfm_flash_test_get_component_img_digest_read_error);
TEST (cfm_flash_test_get_component_bad_magic_number);
TEST (cfm_flash_test_get_platform_id);
TEST (cfm_flash_test_get_platform_id_manifest_allocation);
TEST (cfm_flash_test_get_platform_id_null);
TEST (cfm_flash_test_get_platform_id_verify_never_run);
TEST (cfm_flash_test_is_empty);
TEST (cfm_flash_test_is_empty_null);
TEST (cfm_flash_test_is_empty_verify_never_run);

TEST_SUITE_END;
