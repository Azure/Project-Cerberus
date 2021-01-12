// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_flash.h"
#include "manifest/pcd/pcd_format.h"
#include "flash/spi_flash.h"
#include "mock/flash_master_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "pcd_testing.h"
#include "cmd_interface/device_manager.h"
#include "flash/flash.h"


static const char *SUITE = "pcd_flash";


/**
 * Dependencies for testing PCDs.
 */
struct pcd_flash_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< PCD signature verification. */
	struct flash_master_mock flash_mock;				/**< Flash master for the PCD flash. */
	struct spi_flash flash;								/**< Flash where the PCD is stored. */
	uint32_t addr;										/**< Base address of the PCD. */
	uint8_t signature[256];								/**< Buffer for the manifest signature. */
	uint8_t platform_id[256];							/**< Cache for the platform ID. */
	struct pcd_flash test;								/**< PCD instance under test. */
};


/**
 * Initialize common PCD testing dependencies.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 */
static void pcd_flash_testing_init_dependencies (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&pcd->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&pcd->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&pcd->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&pcd->flash, &pcd->flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&pcd->flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pcd->addr = address;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param pcd The testing components to release.
 */
void pcd_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct pcd_flash_testing *pcd)
{
	int status;

	status = flash_master_mock_validate_and_release (&pcd->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&pcd->verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&pcd->flash);
	HASH_TESTING_ENGINE_RELEASE (&pcd->hash);
}

/**
 * Initialize PCD for testing.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 */
static void pcd_flash_testing_init (CuTest *test, struct pcd_flash_testing *pcd, uint32_t address)
{
	int status;

	pcd_flash_testing_init_dependencies (test, pcd, address);

	status = pcd_flash_init (&pcd->test, &pcd->flash.base, address, pcd->signature,
		sizeof (pcd->signature), pcd->platform_id, sizeof (pcd->platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pcd->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pcd->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param pcd The testing components to release.
 */
static void pcd_flash_testing_validate_and_release (CuTest *test, struct pcd_flash_testing *pcd)
{
	pcd_flash_release (&pcd->test);

	pcd_flash_testing_validate_and_release_dependencies (test, pcd);
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param test The testing framework.
 * @param pcd The testing components.
 * @param data The PCD data to read.
 * @param length The length of the PCD data.
 * @param hash The PCD hash.  Null to skip hash checking.
 * @param signature The PCD signature.
 * @param sig_offset Offset of the PCD signature.
 * @param platform_id_len Length of the platform ID string.
 * @param sig_result Result of the signature verification call.
 */
static void pcd_flash_testing_verify_pcd (CuTest *test, struct pcd_flash_testing *pcd,
	const uint8_t *data, size_t length, const uint8_t *hash, const uint8_t *signature,
	uint32_t sig_offset, size_t platform_id_len, int sig_result)
{
	uint32_t pcd_offset;
	int status;

	status = flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, pcd->addr, 0, -1, PCD_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, signature, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, pcd->addr + sig_offset, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd->flash_mock, pcd->addr, data,
		length - PCD_SIGNATURE_LEN);

	if (hash) {
		status |= mock_expect (&pcd->verification.mock, pcd->verification.base.verify_signature,
			&pcd->verification, sig_result, MOCK_ARG_PTR_CONTAINS (hash, PCD_HASH_LEN),
			MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (signature, PCD_SIGNATURE_LEN),
			MOCK_ARG (PCD_SIGNATURE_LEN));
	}
	else {
		status |= mock_expect (&pcd->verification.mock, pcd->verification.base.verify_signature,
			&pcd->verification, sig_result, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
			MOCK_ARG_PTR_CONTAINS (signature, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));
	}

	CuAssertIntEquals (test, 0, status);

	if (sig_result == 0) {
		/* Structure verification. */
		pcd_offset = PCD_HEADER_SIZE;

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, sizeof (struct pcd_header)));

		pcd_offset += sizeof (struct pcd_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, sizeof (struct pcd_rot_header)));

		pcd_offset += sizeof (struct pcd_rot_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
				sizeof (struct pcd_port_header)));

		pcd_offset += sizeof (struct pcd_port_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
				sizeof (struct pcd_port_header)));

		pcd_offset += sizeof (struct pcd_port_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
				sizeof (struct pcd_components_header)));

		pcd_offset += sizeof (struct pcd_components_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
				sizeof (struct pcd_component_header)));

		pcd_offset += sizeof (struct pcd_component_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
				sizeof (struct pcd_component_header)));

		pcd_offset += sizeof (struct pcd_component_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, sizeof (struct pcd_mux_header)));

		pcd_offset += sizeof (struct pcd_mux_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, sizeof (struct pcd_mux_header)));

		pcd_offset += sizeof (struct pcd_mux_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
				sizeof (struct pcd_platform_header)));

		pcd_offset += sizeof (struct pcd_platform_header);

		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&pcd->flash_mock, 0, data + pcd_offset,
			length - pcd_offset,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, platform_id_len));

		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Initialize a PCD for testing.  Run verification to load the PCD information.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 * @param data The PCD data to read.
 * @param length The length of the PCD data.
 * @param hash The PCD hash.
 * @param signature The PCD signature.
 * @param sig_offset Offset of the PCD signature.
 * @param platform_id_len Length of the platform ID string.
 * @param sig_result Result of the signature verification call.
 */
static void pcd_flash_testing_init_and_verify (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address, const uint8_t *data, size_t length, const uint8_t *hash,
	const uint8_t *signature, uint32_t sig_offset, size_t platform_id_len, int sig_result)
{
	int status;

	pcd_flash_testing_init (test, pcd, address);
	pcd_flash_testing_verify_pcd (test, pcd, data, length, hash, signature, sig_offset,
		platform_id_len, sig_result);

	status = pcd->test.base.base.verify (&pcd->test.base.base, &pcd->hash.base,
		&pcd->verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&pcd->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pcd->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void pcd_flash_test_init (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);

	status = pcd_flash_init (&pcd.test, &pcd.flash.base, 0x10000, pcd.signature,
		sizeof (pcd.signature), pcd.platform_id, sizeof (pcd.platform_id));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, pcd.test.base.base.verify);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_platform_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.free_platform_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_hash);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_signature);

	CuAssertPtrNotNull (test, pcd.test.base.get_devices_info);
	CuAssertPtrNotNull (test, pcd.test.base.get_rot_info);
	CuAssertPtrNotNull (test, pcd.test.base.get_port_info);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&pcd.test.base_flash));
	CuAssertPtrEquals (test, &pcd.flash, manifest_flash_get_flash (&pcd.test.base_flash));

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_init_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);

	status = pcd_flash_init (NULL, &pcd.flash.base, 0x10000, pcd.signature,
		sizeof (pcd.signature), pcd.platform_id, sizeof (pcd.platform_id));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, NULL, 0x10000, pcd.signature,
		sizeof (pcd.signature), pcd.platform_id, sizeof (pcd.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, &pcd.flash.base, 0x10000, NULL,
		sizeof (pcd.signature), pcd.platform_id, sizeof (pcd.platform_id));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, NULL, 0x10000, pcd.signature,
		sizeof (pcd.signature), NULL, sizeof (pcd.platform_id));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release_dependencies (test, &pcd);
}

static void pcd_flash_test_init_manifest_flash_init_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10001);

	status = pcd_flash_init (&pcd.test, &pcd.flash.base, 0x10001, pcd.signature,
		sizeof (pcd.signature), pcd.platform_id, sizeof (pcd.platform_id));
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	pcd_flash_testing_validate_and_release_dependencies (test, &pcd);
}

static void pcd_flash_test_release_null (CuTest *test)
{
	TEST_START;

	pcd_flash_release (NULL);
}

static void pcd_flash_test_verify (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, PCD_DATA, PCD_DATA_LEN, PCD_HASH, PCD_SIGNATURE,
		PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.verify (NULL, &pcd.hash.base, &pcd.verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, NULL, &pcd.verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, NULL, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_rot_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_port_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_components_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_component_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_mux_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_platform_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_platform_id_too_long (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);

	status = pcd_flash_init (&pcd.test, &pcd.flash.base, 0x10000, pcd.signature,
		sizeof (pcd.signature), pcd.platform_id, PCD_PLATFORM_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_platform_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_PLAT_ID_BUFFER_TOO_SMALL, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_platform_id_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
			sizeof (struct pcd_platform_header)));

	status |= flash_master_mock_expect_xfer (&pcd.flash_mock, FLASH_MASTER_XFER_FAILED,
			FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_rot_too_big (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_header pcd_rot_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_rot_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header),
		sizeof (struct pcd_rot_header));
	pcd_rot_header.length = PCD_DATA_LEN;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, (uint8_t*) &pcd_rot_header,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_rot_too_big2 (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_header pcd_rot_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_rot_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header),
		sizeof (struct pcd_rot_header));
	pcd_rot_header.length += 1;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, (uint8_t*) &pcd_rot_header,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_components_too_big (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_components_header pcd_components_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_components_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) +
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header),
		sizeof (struct pcd_components_header));
	pcd_components_header.length = PCD_DATA_LEN;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,
		(uint8_t*) &pcd_components_header, sizeof (struct pcd_components_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
			sizeof (struct pcd_components_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_components_too_big2 (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_components_header pcd_components_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_components_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) +
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header),
		sizeof (struct pcd_components_header));
	pcd_components_header.length += 1;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,
		(uint8_t*) &pcd_components_header, sizeof (struct pcd_components_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
			sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_component_too_big (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_component_header pcd_component_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_component_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) +
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) +
		sizeof (struct pcd_components_header), sizeof (struct pcd_component_header));
	pcd_component_header.length = PCD_DATA_LEN;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,
		(uint8_t*) &pcd_component_header, sizeof (struct pcd_component_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
			sizeof (struct pcd_component_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_component_too_big2 (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_component_header pcd_component_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_component_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) +
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) +
		sizeof (struct pcd_components_header), sizeof (struct pcd_component_header));
	pcd_component_header.length += 1;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,
		(uint8_t*) &pcd_component_header, sizeof (struct pcd_component_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
			sizeof (struct pcd_component_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_pcd_platform_too_big (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_platform_header pcd_platform_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_platform_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) +
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) +
		sizeof (struct pcd_components_header) + 2 * sizeof (struct pcd_component_header) +
		2 * sizeof (struct pcd_mux_header), sizeof (struct pcd_platform_header));
	pcd_platform_header.length += 1;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, (uint8_t*) &pcd_platform_header,
		sizeof (struct pcd_platform_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_platform_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_invalid_pcd_platform_header_header_len (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_platform_header pcd_platform_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_platform_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) +
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) +
		sizeof (struct pcd_components_header) + 2 * sizeof (struct pcd_component_header) +
		2 * sizeof (struct pcd_mux_header), sizeof (struct pcd_platform_header));
	pcd_platform_header.header_len += 1;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA,
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&pcd.verification.mock, pcd.verification.base.verify_signature,
		&pcd.verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, (uint8_t*) &pcd_platform_header,
		sizeof (struct pcd_platform_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_platform_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_HDR_LEN, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_bad_magic_number (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.hash.base, &pcd.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&pcd.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH, hash_out, PCD_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_after_verify (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH, hash_out, PCD_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_hash (NULL, &pcd.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, NULL, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_bad_magic_num (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[PCD_SIGNATURE_LEN];
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_SIGNATURE_LEN, status);

	status = testing_validate_array (PCD_SIGNATURE, sig_out, PCD_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_after_verify (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[PCD_SIGNATURE_LEN];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_SIGNATURE_LEN, status);

	status = testing_validate_array (PCD_SIGNATURE, sig_out, PCD_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, id);
	CuAssertStrEquals (test, PCD_PLATFORM_ID, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_manifest_allocation (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char *id = NULL;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, PCD_PLATFORM_ID, id);

	pcd.test.base.base.free_platform_id (&pcd.test.base.base, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char *id = NULL;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.base.get_platform_id (NULL, &id, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	size_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,
		PCD_DATA + PCD_COMPONENTS_OFFSET, sizeof (struct pcd_components_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1,
			sizeof (struct pcd_components_header)));

	pcd_offset = PCD_COMPONENTS_OFFSET + sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, num_devices);
	CuAssertPtrNotNull (test, devices_info);

	CuAssertIntEquals (test, 0x10, devices_info[0].smbus_addr);
	CuAssertIntEquals (test, 0x0C, devices_info[0].eid);
	CuAssertIntEquals (test, 0x15, devices_info[1].smbus_addr);
	CuAssertIntEquals (test, 0x0D, devices_info[1].eid);

	platform_free (devices_info);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.get_devices_info (NULL, &devices_info, &num_devices);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_devices_info (&pcd.test.base, NULL, &num_devices);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info_pcd_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_HEADER_SIZE, PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info_rot_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_ROT_OFFSET, PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info_components_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,	PCD_DATA + PCD_ROT_OFFSET,
		PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_COMPONENTS_OFFSET, PCD_DATA_LEN - PCD_COMPONENTS_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1,
		sizeof (struct pcd_components_header)));

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_devices_info_component_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct device_manager_info *devices_info;
	size_t num_devices;
	size_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0,
		PCD_DATA + PCD_COMPONENTS_OFFSET, sizeof (struct pcd_components_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1,
			sizeof (struct pcd_components_header)));

	pcd_offset = PCD_COMPONENTS_OFFSET + sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + pcd_offset, sizeof (struct pcd_component_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
			sizeof (struct pcd_component_header)));

	status = pcd.test.base.get_devices_info (&pcd.test.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertIntEquals (test, 0, num_devices);
	CuAssertPtrEquals (test, NULL, devices_info);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, info.is_pa_rot);
	CuAssertIntEquals (test, 0x41, info.i2c_slave_addr);
	CuAssertIntEquals (test, 0x10, info.bmc_i2c_addr);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.get_rot_info (NULL, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_rot_info (&pcd.test.base, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_pcd_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_HEADER_SIZE, PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_rot_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_ROT_OFFSET, PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	size_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 48000000, info.spi_freq);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	status = pcd.test.base.get_port_info (&pcd.test.base, 1, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32000000, info.spi_freq);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = pcd.test.base.get_port_info (NULL, 0, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_pcd_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_HEADER_SIZE, PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_rot_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + PCD_ROT_OFFSET, PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_port_header_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	size_t pcd_offset;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, FLASH_NO_MEMORY,
		PCD_DATA + pcd_offset, sizeof (struct pcd_port_header),
		FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, sizeof (struct pcd_port_header)));

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_port_id_invalid (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	size_t pcd_offset;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, PCD_DATA, PCD_DATA_LEN, PCD_HASH,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_PLATFORM_ID_LEN, 0);

	status = flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1,
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&pcd.flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	status = pcd.test.base.get_port_info (&pcd.test.base, 2, &info);
	CuAssertIntEquals (test, PCD_INVALID_PORT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}


CuSuite* get_pcd_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcd_flash_test_init);
	SUITE_ADD_TEST (suite, pcd_flash_test_init_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_init_manifest_flash_init_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_release_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_rot_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_port_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_components_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_component_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_mux_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_platform_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_platform_id_too_long);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_platform_id_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_rot_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_rot_too_big2);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_components_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_components_too_big2);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_component_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_component_too_big2);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_platform_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_invalid_pcd_platform_header_header_len);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_bad_magic_number);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_id);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_id_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_id_verify_never_run);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash_after_verify);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature_after_verify);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature_bad_magic_number);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_manifest_allocation);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_verify_never_run);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_verify_never_run);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_components_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_component_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_verify_never_run);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_verify_never_run);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_port_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_port_id_invalid);

	return suite;
}
