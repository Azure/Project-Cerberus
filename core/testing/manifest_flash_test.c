// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_flash.h"
#include "manifest/manifest_format.h"
#include "manifest/manifest.h"
#include "mock/flash_master_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "crypto/ecc.h"
#include "pfm_testing.h"


static const char *SUITE = "manifest_flash";


/*******************
 * Test cases
 *******************/

static void manifest_flash_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_verify (NULL, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_verify (&manifest, NULL, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_verify (&manifest, &hash.base, NULL, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_sig_longer_than_pfm (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_sig_same_length_as_pfm (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) PFM_DATA_LEN;
	pfm_bad_data[9] = PFM_DATA_LEN >> 8;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_sig_length_into_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) (PFM_DATA_LEN - PFM_HEADER_SIZE + 1);
	pfm_bad_data[9] = (PFM_DATA_LEN - PFM_HEADER_SIZE + 1) >> 8;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_sig_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[sizeof (pfm_bad_data) - 1] ^= 0x55;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_bad_data,
		sizeof (pfm_bad_data));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PFM_SIGNATURE, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_bad_signature_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_sig[PFM_SIGNATURE_LEN];

	TEST_START;

	memcpy (pfm_bad_sig, &PFM_DATA[PFM_SIGNATURE_OFFSET], sizeof (pfm_bad_sig));
	pfm_bad_sig[sizeof (pfm_bad_sig) - 1] ^= 0x55;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_sig, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN),
		MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_bad_signature_ecc_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_sig[PFM_SIGNATURE_LEN];

	TEST_START;

	memcpy (pfm_bad_sig, &PFM_DATA[PFM_SIGNATURE_OFFSET], sizeof (pfm_bad_sig));
	pfm_bad_sig[sizeof (pfm_bad_sig) - 1] ^= 0x55;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_sig, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN),
		MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_verify_read_error_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	memcpy (hash_out, empty, sizeof (hash_out));

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (empty));
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_id (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_id (&manifest, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_id_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_id (NULL, &id);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_id (&manifest, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_id_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_id (&manifest, &id);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_id_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	int status;
	uint32_t id;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_id (&manifest, &id);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_sig[PFM_SIGNATURE_LEN];

	TEST_START;

	memcpy (pfm_bad_sig, &PFM_DATA[PFM_SIGNATURE_OFFSET], sizeof (pfm_bad_sig));
	pfm_bad_sig[sizeof (pfm_bad_sig) - 1] ^= 0x55;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_sig, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (PFM_HASH, PFM_HASH_LEN),
		MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify_bad_sig_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_after_verify_sig_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
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

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH, hash_out, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_hash (NULL, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_hash (&manifest, NULL, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, NULL, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_header_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_sig_longer_than_pfm (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_sig_same_length_as_pfm (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) PFM_DATA_LEN;
	pfm_bad_data[9] = PFM_DATA_LEN >> 8;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_hash_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
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

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_flash_test_get_signature (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, status);

	status = testing_validate_array (PFM_SIGNATURE, sig_out, PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_signature_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_signature (&manifest, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_signature_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_signature_small_sig_buffer (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN - 1];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_SIG_BUFFER_TOO_SMALL, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_signature_sig_longer_than_pfm (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	*((uint16_t*) pfm_bad_data) = PFM_SIGNATURE_LEN - 1;	// Set the total PFM length.

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_get_signature_sig_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	uint8_t sig_out[PFM_SIGNATURE_LEN];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_DATA_LEN, header.length);
	CuAssertIntEquals (test, PFM_MAGIC_NUM, header.magic);
	CuAssertIntEquals (test, 1, header.id);
	CuAssertIntEquals (test, PFM_SIGNATURE_LEN, header.sig_length);
	CuAssertIntEquals (test, 0, header.reserved);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = manifest_flash_read_header (NULL, &header);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_read_header (&manifest, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_bad_magic_number (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data,
		PFM_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_sig_longer_than_pfm (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_sig_same_length_as_pfm (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) PFM_DATA_LEN;
	pfm_bad_data[9] = PFM_DATA_LEN >> 8;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_sig_length_into_header (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) (PFM_DATA_LEN - PFM_HEADER_SIZE + 1);
	pfm_bad_data[9] = (PFM_DATA_LEN - PFM_HEADER_SIZE + 1) >> 8;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void manifest_flash_test_read_header_only_header_and_sig (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct manifest_flash manifest;
	struct manifest_header header;
	int status;
	uint8_t pfm_bad_data[PFM_HEADER_SIZE];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[8] = (uint8_t) (PFM_DATA_LEN - PFM_HEADER_SIZE);
	pfm_bad_data[9] = (PFM_DATA_LEN - PFM_HEADER_SIZE) >> 8;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_init (&manifest, &flash, 0x10000, PFM_MAGIC_NUM);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_header (&manifest, &header);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_DATA_LEN, header.length);
	CuAssertIntEquals (test, PFM_MAGIC_NUM, header.magic);
	CuAssertIntEquals (test, 1, header.id);
	CuAssertIntEquals (test, PFM_DATA_LEN - PFM_HEADER_SIZE, header.sig_length);
	CuAssertIntEquals (test, 0, header.reserved);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}


CuSuite* get_manifest_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, manifest_flash_test_init);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_with_hash_out);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_null);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_small_hash_buffer);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_header_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_bad_magic_number);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_sig_longer_than_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_sig_same_length_as_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_sig_length_into_header);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_sig_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_bad_signature);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_bad_signature_ecc_with_hash_out);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_bad_signature_with_hash_out);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_verify_read_error_with_hash_out);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_id);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_id_null);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_id_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_id_bad_magic_num);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify_bad_signature);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify_header_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify_bad_magic_number);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify_bad_sig_length);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_after_verify_sig_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_null);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_small_hash_buffer);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_header_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_bad_magic_number);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_sig_longer_than_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_sig_same_length_as_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_hash_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature_null);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature_header_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature_bad_magic_number);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature_small_sig_buffer);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature_sig_longer_than_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_get_signature_sig_read_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_null);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_error);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_bad_magic_number);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_sig_longer_than_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_sig_same_length_as_pfm);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_sig_length_into_header);
	SUITE_ADD_TEST (suite, manifest_flash_test_read_header_only_header_and_sig);

	return suite;
}
