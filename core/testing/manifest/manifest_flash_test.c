// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_flash.h"
#include "manifest/manifest_format.h"
#include "manifest/manifest.h"
#include "flash/spi_flash.h"
#include "crypto/ecc.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/pfm_testing.h"


TEST_SUITE_LABEL ("manifest_flash");

/**
 * Dependencies for testing manifests.
 */
struct manifest_flash_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< PFM signature verification. */
	struct flash_master_mock flash_mock;				/**< Flash master for the PFM flash. */
	struct spi_flash_state state;						/**< PFM flash context. */
	struct spi_flash flash;								/**< Flash where the PFM is stored. */
	uint32_t addr;										/**< Base address of the PFM. */
	struct manifest_flash test;							/**< Manifest instance for common testing. */
};


/**
 * Initialize common manifest testing dependencies.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 */
static void manifest_flash_testing_init_dependencies (CuTest *test,
	struct manifest_flash_testing *manifest, uint32_t address)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&manifest->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&manifest->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&manifest->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&manifest->flash, &manifest->state, &manifest->flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manifest->flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest->addr = address;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param manifest The testing components to release.
 */
void manifest_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct manifest_flash_testing *manifest)
{
	int status;

	status = flash_master_mock_validate_and_release (&manifest->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&manifest->verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&manifest->flash);
	HASH_TESTING_ENGINE_RELEASE (&manifest->hash);
}

/**
 * Set expectations for common initialization flows.
 *
 * @param test The testing framawork.
 * @param manifest The components for the test.
 * @param block_size The flash block size to report.
 */
static void manifest_flash_testing_init_common (CuTest *test,
	struct manifest_flash_testing *manifest, uint32_t block_size)
{

}

/**
 * Initialize manifest for testing.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 * @param magic_v1 The manifest v1 type identifier.
 */
static void manifest_flash_testing_init (CuTest *test, struct manifest_flash_testing *manifest,
	uint32_t address, uint16_t magic_v1)
{
	int status;

	manifest_flash_testing_init_dependencies (test, manifest, address);
	manifest_flash_testing_init_common (test, manifest, 0x1000);

	status = manifest_flash_init (&manifest->test, &manifest->flash.base, address, magic_v1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param manifest The testing components to release.
 */
static void manifest_flash_testing_validate_and_release (CuTest *test,
	struct manifest_flash_testing *manifest)
{
	manifest_flash_release (&manifest->test);

	manifest_flash_testing_validate_and_release_dependencies (test, manifest);
}

/**
 * Set expectations on mocks for manifest verification.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param manifest_data The manifest being verified.
 * @param manifest_data_len Length of the manifest data.
 * @param manifest_sig The signature for the manifest.
 * @param manifest_sig_offset Offset of the manifest signature.
 * @param manifest_sig_len Length of the manifest signature.
 * @param manifest_hash Hash of the manifest data.
 * @param sig_result Result of the signature verification call.
 */
void manifest_flash_testing_verify_manifest (CuTest *test, struct manifest_flash_testing *manifest,
	const uint8_t *manifest_data, size_t manifest_data_len, const uint8_t *manifest_sig,
	uint32_t manifest_sig_offset, size_t manifest_sig_len, const uint8_t *manifest_hash,
	int sig_result)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (&manifest->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest->flash_mock, 0, manifest_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, manifest->addr, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest->flash_mock, 0, manifest_sig,
		manifest_sig_len,
		FLASH_EXP_READ_CMD (0x03, manifest->addr + manifest_sig_offset, 0, -1, manifest_sig_len));

	status |= flash_master_mock_expect_verify_flash (&manifest->flash_mock, manifest->addr,
		manifest_data, manifest_data_len - manifest_sig_len);

	status |= mock_expect (&manifest->verification.mock,
		manifest->verification.base.verify_signature, &manifest->verification, sig_result,
		MOCK_ARG_PTR_CONTAINS (manifest_hash, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (manifest_sig, manifest_sig_len), MOCK_ARG (manifest_sig_len));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a manifest for testing.  Run verification to load the manifest information.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 * @param magic_v1 The manifest v1 type identifier.
 * @param manifest_data The manifest being verified.
 * @param manifest_data_len Length of the manifest data.
 * @param manifest_sig The signature for the manifest.
 * @param manifest_sig_offset Offset of the manifest signature.
 * @param manifest_sig_len Length of the manifest signature.
 * @param manifest_hash Hash of the manifest data.
 * @param sig_result Result of the signature verification call.
 */
static void manifest_flash_testing_init_and_verify (CuTest *test,
	struct manifest_flash_testing *manifest, uint32_t address, uint16_t magic_v1,
	const uint8_t *manifest_data, size_t manifest_data_len, const uint8_t *manifest_sig,
	uint32_t manifest_sig_offset, size_t manifest_sig_len, const uint8_t *manifest_hash,
	int sig_result)
{
	int status;

	manifest_flash_testing_init (test, manifest, address, magic_v1);
	manifest_flash_testing_verify_manifest (test, manifest, manifest_data,
		manifest_data_len, manifest_sig, manifest_sig_offset, manifest_sig_len, manifest_hash,
		sig_result);

	status = manifest_flash_verify (&manifest->test, &manifest->hash.base,
		&manifest->verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&manifest->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void manifest_flash_test_init (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init_dependencies (test, &manifest, 0x10000);

	status = manifest_flash_init (&manifest.test, &manifest.flash.base, 0x10000, PFM_MAGIC_NUM);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&manifest.test));
	CuAssertPtrEquals (test, &manifest.flash, manifest_flash_get_flash (&manifest.test));

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_flash_release (NULL);
}

static void manifest_flash_test_get_addr_null (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, 0, manifest_flash_get_addr (NULL));
}

static void manifest_flash_test_get_flash_null (CuTest *test)
{
	TEST_START;

	CuAssertPtrEquals (test, NULL, manifest_flash_get_flash (NULL));
}

static void manifest_flash_test_verify (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_with_hash_out (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_null (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_verify (NULL, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_verify (&manifest.test, NULL,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		NULL, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_small_hash_buffer (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_bad_magic_number (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_sig_longer_than_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_sig_same_length_as_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) PFM_DATA_LEN;
	pfm_bad_data[9] = PFM_DATA_LEN >> 8;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_sig_length_into_header (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) (PFM_DATA_LEN - PFM_HEADER_SIZE + 1);
	pfm_bad_data[9] = (PFM_DATA_LEN - PFM_HEADER_SIZE + 1) >> 8;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_sig_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_bad_signature_with_hash_out (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, RSA_ENGINE_BAD_SIGNATURE);

	memset (hash_out, 0, sizeof (hash_out));

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_bad_signature_ecc_with_hash_out (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, ECC_ENGINE_BAD_SIGNATURE);

	memset (hash_out, 0, sizeof (hash_out));

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_verify_read_error_with_hash_out (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0xff, sizeof (hash_out));

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (empty));
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_id (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_id_null (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_id (NULL, &id);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_id (&manifest.test, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_id_verify_never_run (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_id_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_id_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manifest.flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manifest.flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH ,RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manifest.flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify_bad_magic_number (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manifest.flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify_bad_sig_length (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manifest.flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_after_verify_sig_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manifest.flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_HASH_LEN, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_null (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_hash (NULL, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_hash (&manifest.test, NULL, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_small_hash_buffer (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_header_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_bad_magic_number (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_sig_longer_than_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_sig_same_length_as_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) PFM_DATA_LEN;
	pfm_bad_data[9] = PFM_DATA_LEN >> 8;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_hash_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	manifest_flash_testing_verify_manifest (test, &manifest, PFM_DATA, PFM_DATA_LEN, PFM_SIGNATURE,
		PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify_bad_magic_number (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify_bad_sig_length (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_after_verify_sig_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&manifest.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_SIGNATURE,
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_null (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_signature (&manifest.test, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_header_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_small_sig_buffer (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN - 1];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_SIG_BUFFER_TOO_SMALL, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_sig_longer_than_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	*((uint16_t*) pfm_bad_data) = PFM_SIGNATURE_LEN - 1;	// Set the total PFM length.

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_get_signature_sig_read_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_DATA_LEN, header.length);
	CuAssertIntEquals (test, PFM_MAGIC_NUM, header.magic);
	CuAssertIntEquals (test, 1, header.id);
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, header.sig_length);
	CuAssertIntEquals (test, 0, header.reserved);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_null (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_read_header (NULL, &header);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_read_header (&manifest.test, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_error (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&manifest.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_bad_magic_number (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_sig_longer_than_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_sig_same_length_as_pfm (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) PFM_DATA_LEN;
	pfm_bad_data[9] = PFM_DATA_LEN >> 8;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_sig_length_into_header (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) (PFM_DATA_LEN - PFM_HEADER_SIZE + 1);
	pfm_bad_data[9] = (PFM_DATA_LEN - PFM_HEADER_SIZE + 1) >> 8;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_read_header_only_header_and_sig (CuTest *test)
{
	struct manifest_flash_testing manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) (PFM_DATA_LEN - PFM_HEADER_SIZE);
	pfm_bad_data[9] = (PFM_DATA_LEN - PFM_HEADER_SIZE) >> 8;

	manifest_flash_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manifest.flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest.test, &header);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_DATA_LEN, header.length);
	CuAssertIntEquals (test, PFM_MAGIC_NUM, header.magic);
	CuAssertIntEquals (test, 1, header.id);
	CuAssertIntEquals (test, PFM_DATA_LEN - PFM_HEADER_SIZE, header.sig_length);
	CuAssertIntEquals (test, 0, header.reserved);

	manifest_flash_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_test_compare_id_higher (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET ,PFM_SIGNATURE_LEN, PFM_HASH, 0);
	manifest_flash_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_SIGNATURE, PFM_SIGNATURE_OFFSET ,PFM_SIGNATURE_LEN, PFM2_HASH, 0);

	status = manifest_flash_compare_id (&manifest1.test, &manifest2.test);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_lower (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);
	manifest_flash_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM2_HASH, 0);

	status = manifest_flash_compare_id (&manifest2.test, &manifest1.test);
	CuAssertIntEquals (test, 1, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_equal (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);
	manifest_flash_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_compare_id (&manifest1.test, &manifest2.test);
	CuAssertIntEquals (test, 1, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_no_manifest1 (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest1, 0x10000, PFM_MAGIC_NUM);
	manifest_flash_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_compare_id (&manifest1.test, &manifest2.test);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_no_manifest2 (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);
	manifest_flash_testing_init (test, &manifest2, 0x20000, PFM_MAGIC_NUM);

	status = manifest_flash_compare_id (&manifest1.test, &manifest2.test);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_no_manifests (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init (test, &manifest1, 0x10000, PFM_MAGIC_NUM);
	manifest_flash_testing_init (test, &manifest2, 0x20000, PFM_MAGIC_NUM);

	status = manifest_flash_compare_id (&manifest1.test, &manifest2.test);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_null_manifest1 (CuTest *test)
{
	struct manifest_flash_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_compare_id (NULL, &manifest2.test);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_test_compare_id_null_manifest2 (CuTest *test)
{
	struct manifest_flash_testing manifest1;
	int status;

	TEST_START;

	manifest_flash_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM, PFM_DATA,
		PFM_DATA_LEN, PFM_SIGNATURE, PFM_SIGNATURE_OFFSET, PFM_SIGNATURE_LEN, PFM_HASH, 0);

	status = manifest_flash_compare_id (&manifest1.test, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_testing_validate_and_release (test, &manifest1);
}

static void manifest_flash_test_compare_id_both_null (CuTest *test)
{
	int status;

	TEST_START;

	status = manifest_flash_compare_id (NULL, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);
}


TEST_SUITE_START (manifest_flash);

TEST (manifest_flash_test_init);
TEST (manifest_flash_test_release_null);
TEST (manifest_flash_test_get_addr_null);
TEST (manifest_flash_test_get_flash_null);
TEST (manifest_flash_test_verify);
TEST (manifest_flash_test_verify_with_hash_out);
TEST (manifest_flash_test_verify_null);
TEST (manifest_flash_test_verify_small_hash_buffer);
TEST (manifest_flash_test_verify_header_read_error);
TEST (manifest_flash_test_verify_bad_magic_number);
TEST (manifest_flash_test_verify_sig_longer_than_pfm);
TEST (manifest_flash_test_verify_sig_same_length_as_pfm);
TEST (manifest_flash_test_verify_sig_length_into_header);
TEST (manifest_flash_test_verify_sig_read_error);
TEST (manifest_flash_test_verify_bad_signature);
TEST (manifest_flash_test_verify_bad_signature_with_hash_out);
TEST (manifest_flash_test_verify_bad_signature_ecc_with_hash_out);
TEST (manifest_flash_test_verify_read_error);
TEST (manifest_flash_test_verify_read_error_with_hash_out);
TEST (manifest_flash_test_get_id);
TEST (manifest_flash_test_get_id_null);
TEST (manifest_flash_test_get_id_verify_never_run);
TEST (manifest_flash_test_get_id_after_verify_header_read_error);
TEST (manifest_flash_test_get_id_after_verify_bad_signature);
TEST (manifest_flash_test_get_hash);
TEST (manifest_flash_test_get_hash_after_verify);
TEST (manifest_flash_test_get_hash_after_verify_error);
TEST (manifest_flash_test_get_hash_after_verify_bad_signature);
TEST (manifest_flash_test_get_hash_after_verify_header_read_error);
TEST (manifest_flash_test_get_hash_after_verify_bad_magic_number);
TEST (manifest_flash_test_get_hash_after_verify_bad_sig_length);
TEST (manifest_flash_test_get_hash_after_verify_sig_read_error);
TEST (manifest_flash_test_get_hash_null);
TEST (manifest_flash_test_get_hash_small_hash_buffer);
TEST (manifest_flash_test_get_hash_header_read_error);
TEST (manifest_flash_test_get_hash_bad_magic_number);
TEST (manifest_flash_test_get_hash_sig_longer_than_pfm);
TEST (manifest_flash_test_get_hash_sig_same_length_as_pfm);
TEST (manifest_flash_test_get_hash_read_error);
TEST (manifest_flash_test_get_signature);
TEST (manifest_flash_test_get_signature_after_verify);
TEST (manifest_flash_test_get_signature_after_verify_error);
TEST (manifest_flash_test_get_signature_after_verify_bad_signature);
TEST (manifest_flash_test_get_signature_after_verify_header_read_error);
TEST (manifest_flash_test_get_signature_after_verify_bad_magic_number);
TEST (manifest_flash_test_get_signature_after_verify_bad_sig_length);
TEST (manifest_flash_test_get_signature_after_verify_sig_read_error);
TEST (manifest_flash_test_get_signature_null);
TEST (manifest_flash_test_get_signature_header_read_error);
TEST (manifest_flash_test_get_signature_bad_magic_number);
TEST (manifest_flash_test_get_signature_small_sig_buffer);
TEST (manifest_flash_test_get_signature_sig_longer_than_pfm);
TEST (manifest_flash_test_get_signature_sig_read_error);
TEST (manifest_flash_test_read_header);
TEST (manifest_flash_test_read_header_null);
TEST (manifest_flash_test_read_header_error);
TEST (manifest_flash_test_read_header_bad_magic_number);
TEST (manifest_flash_test_read_header_sig_longer_than_pfm);
TEST (manifest_flash_test_read_header_sig_same_length_as_pfm);
TEST (manifest_flash_test_read_header_sig_length_into_header);
TEST (manifest_flash_test_read_header_only_header_and_sig);
TEST (manifest_flash_test_compare_id_higher);
TEST (manifest_flash_test_compare_id_lower);
TEST (manifest_flash_test_compare_id_equal);
TEST (manifest_flash_test_compare_id_no_manifest1);
TEST (manifest_flash_test_compare_id_no_manifest2);
TEST (manifest_flash_test_compare_id_no_manifests);
TEST (manifest_flash_test_compare_id_null_manifest1);
TEST (manifest_flash_test_compare_id_null_manifest2);
TEST (manifest_flash_test_compare_id_both_null);

TEST_SUITE_END;
