// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "keystore/keystore_flash_encrypted.h"
#include "mock/flash_master_mock.h"
#include "mock/aes_mock.h"
#include "mock/rng_mock.h"
#include "engines/aes_testing_engine.h"
#include "rsa_testing.h"
#include "aes_testing.h"


static const char *SUITE = "keystore_flash_encrypted";


/*******************
 * Test cases
 *******************/

static void keystore_flash_encrypted_test_init (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_not_block_aligned (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x11000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_null (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (NULL, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_encrypted_init (&store, NULL, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, NULL, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_not_sector_aligned (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10001, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_no_keys (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x1000, -1, &aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_NO_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_not_enough_space (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x1c000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INSUFFICIENT_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_decreasing_sectors (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_decreasing_sectors_not_block_aligned (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x11000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_decreasing_sectors_null (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (NULL, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, NULL, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		NULL, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_decreasing_sectors_not_sector_aligned (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10001, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_decreasing_sectors_no_keys (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x1000, -1,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_NO_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_init_decreasing_sectors_not_enough_space (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x3000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, KEYSTORE_INSUFFICIENT_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_release_null (CuTest *test)
{
	TEST_START;

	keystore_flash_encrypted_release (NULL);
}

static void keystore_flash_encrypted_test_save_key (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + AES_RSA_PRIVKEY_DER_LEN, auth,
		sizeof (auth));

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_not_first_sector (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x13000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x13000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x13002, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0x13002 + AES_RSA_PRIVKEY_DER_LEN, auth,
		sizeof (auth));

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 3, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_max_length (CuTest *test)
{
	AES_TESTING_ENGINE aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t key[4096 - AES_IV_LEN - AES_GCM_TAG_LEN - 2];
	size_t key_len = sizeof (key);

	TEST_START;

	status = AES_TESTING_ENGINE_INIT (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes.base.set_key (&aes.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &key_len, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, NULL, sizeof (key));
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + sizeof (key), NULL,
		AES_IV_LEN + AES_GCM_TAG_LEN);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, key, key_len);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
	AES_TESTING_ENGINE_RELEASE (&aes);
}

static void keystore_flash_encrypted_test_save_key_decreasing_sectors (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + AES_RSA_PRIVKEY_DER_LEN, auth,
		sizeof (auth));

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_decreasing_sectors_not_first_sector (
	CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0xd000);
	status |= flash_master_mock_expect_write (&flash_mock, 0xd000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0xd002, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0xd002 + AES_RSA_PRIVKEY_DER_LEN, auth,
		sizeof (auth));

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 3, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_null (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (NULL, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = store.base.save_key (&store.base, 0, NULL, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_too_long (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER,
		(4096 - AES_IV_LEN - AES_GCM_TAG_LEN - 2) + 1);
	CuAssertIntEquals (test, KEYSTORE_KEY_TOO_LONG, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_id_out_of_range (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 5, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_negative_id (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, -1, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_iv_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_encrypt_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, AES_ENGINE_ENCRYPT_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, AES_ENGINE_ENCRYPT_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_erase_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_write_length_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_write_key_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_write_key_incomplete (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, AES_RSA_PRIVKEY_DER, 254);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_write_tag_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&aes.mock, aes.base.encrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN),
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&aes.mock, 4, AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN, 5);
	status |= mock_expect_output (&aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000,
		(uint8_t*) &AES_RSA_PRIVKEY_DER_LEN, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_save_key_write_tag_incomplete (CuTest *test)
{
	AES_TESTING_ENGINE aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t key[256 - 2 - 1];
	size_t key_len = sizeof (key);

	TEST_START;

	status = AES_TESTING_ENGINE_INIT (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes.base.set_key (&aes.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &key_len, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, NULL, sizeof (key));
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + sizeof (key), NULL, 1);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, key, key_len);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
	AES_TESTING_ENGINE_RELEASE (&aes);
}

static void keystore_flash_encrypted_test_load_key (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, auth, sizeof (auth),
		FLASH_EXP_READ_CMD (0x03, 0x10002 + AES_RSA_PRIVKEY_DER_LEN, 0, -1, sizeof (auth)));

	status |= mock_expect (&aes.mock, aes.base.decrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_output (&aes.mock, 5, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, 6);

	CuAssertIntEquals (test, 0, status);

	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, key_len);

	status = testing_validate_array (RSA_PRIVKEY_DER, key, key_len);
	CuAssertIntEquals (test, 0, status);

	platform_free (key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_not_first_sector (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x12000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x12002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, auth, sizeof (auth),
		FLASH_EXP_READ_CMD (0x03, 0x12002 + AES_RSA_PRIVKEY_DER_LEN, 0, -1, sizeof (auth)));

	status |= mock_expect (&aes.mock, aes.base.decrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_output (&aes.mock, 5, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, 6);

	CuAssertIntEquals (test, 0, status);

	status = store.base.load_key (&store.base, 2, &key, &key_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, key_len);

	status = testing_validate_array (RSA_PRIVKEY_DER, key, key_len);
	CuAssertIntEquals (test, 0, status);

	platform_free (key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_decreasing_sectors (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, auth, sizeof (auth),
		FLASH_EXP_READ_CMD (0x03, 0x10002 + AES_RSA_PRIVKEY_DER_LEN, 0, -1, sizeof (auth)));

	status |= mock_expect (&aes.mock, aes.base.decrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_output (&aes.mock, 5, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, 6);

	CuAssertIntEquals (test, 0, status);

	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, key_len);

	status = testing_validate_array (RSA_PRIVKEY_DER, key, key_len);
	CuAssertIntEquals (test, 0, status);

	platform_free (key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_decreasing_sectors_not_first_sector (
	CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0xe000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0xe002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, auth, sizeof (auth),
		FLASH_EXP_READ_CMD (0x03, 0xe002 + AES_RSA_PRIVKEY_DER_LEN, 0, -1, sizeof (auth)));

	status |= mock_expect (&aes.mock, aes.base.decrypt_data, &aes, 0,
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_output (&aes.mock, 5, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, 6);

	CuAssertIntEquals (test, 0, status);

	status = store.base.load_key (&store.base, 2, &key, &key_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, key_len);

	status = testing_validate_array (RSA_PRIVKEY_DER, key, key_len);
	CuAssertIntEquals (test, 0, status);

	platform_free (key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_null (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (NULL, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, key);

	status = store.base.load_key (&store.base, 0, NULL, &key_len);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_id_out_of_range (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 5, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_negative_id (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, -1, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_tag_mismatch (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, auth, sizeof (auth),
		FLASH_EXP_READ_CMD (0x03, 0x10002 + AES_RSA_PRIVKEY_DER_LEN, 0, -1, sizeof (auth)));

	status |= mock_expect (&aes.mock, aes.base.decrypt_data, &aes, AES_ENGINE_GCM_AUTH_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_BAD_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_bad_length (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = (4096 - AES_IV_LEN - AES_GCM_TAG_LEN - 2) + 1;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_read_length_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_read_key_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_read_tag_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_load_key_decrypt_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;
	uint16_t read_len = AES_RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t auth[AES_IV_LEN + AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (auth, AES_IV, AES_IV_LEN);
	memcpy (&auth[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, AES_RSA_PRIVKEY_DER,
		AES_RSA_PRIVKEY_DER_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, AES_RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, auth, sizeof (auth),
		FLASH_EXP_READ_CMD (0x03, 0x10002 + AES_RSA_PRIVKEY_DER_LEN, 0, -1, sizeof (auth)));

	status |= mock_expect (&aes.mock, aes.base.decrypt_data, &aes, AES_ENGINE_DECRYPT_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_DER, AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_RSA_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, AES_ENGINE_DECRYPT_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key_not_first_sector (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x13000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key_decreasing_sectors (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key_decreasing_sectors_not_first_sector (
	CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init_decreasing_sectors (&store, &flash, 0x10000, 4,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x0d000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key_null (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (NULL, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key_id_out_of_range (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 5);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_test_erase_key_negative_id (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, -1);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_encrypted_test_erase_key_erase_error (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash_encrypted store;
	int status;

	TEST_START;

	status = aes_mock_init (&aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_encrypted_init (&store, &flash, 0x10000, 4, &aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&aes);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_encrypted_release (&store);

	spi_flash_release (&flash);
}


CuSuite* get_keystore_flash_encrypted_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_not_block_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_null);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_not_sector_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_no_keys);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_not_enough_space);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_decreasing_sectors);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_decreasing_sectors_not_block_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_decreasing_sectors_null);
	SUITE_ADD_TEST (suite,
		keystore_flash_encrypted_test_init_decreasing_sectors_not_sector_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_decreasing_sectors_no_keys);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_init_decreasing_sectors_not_enough_space);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_release_null);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_max_length);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_decreasing_sectors);
	SUITE_ADD_TEST (suite,
		keystore_flash_encrypted_test_save_key_decreasing_sectors_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_null);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_too_long);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_id_out_of_range);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_negative_id);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_iv_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_encrypt_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_erase_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_write_length_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_write_key_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_write_key_incomplete);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_write_tag_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_save_key_write_tag_incomplete);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_decreasing_sectors);
	SUITE_ADD_TEST (suite,
		keystore_flash_encrypted_test_load_key_decreasing_sectors_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_null);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_id_out_of_range);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_negative_id);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_tag_mismatch);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_bad_length);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_read_length_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_read_key_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_read_tag_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_load_key_decrypt_error);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_erase_key);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_erase_key_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_erase_key_decreasing_sectors);
	SUITE_ADD_TEST (suite,
		keystore_flash_encrypted_test_erase_key_decreasing_sectors_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_erase_key_null);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_erase_key_id_out_of_range);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_negative_id);
	SUITE_ADD_TEST (suite, keystore_flash_encrypted_test_erase_key_erase_error);

	return suite;
}
