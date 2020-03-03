// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "keystore/keystore_flash.h"
#include "mock/flash_master_mock.h"
#include "mock/hash_mock.h"
#include "engines/hash_testing_engine.h"
#include "rsa_testing.h"


static const char *SUITE = "keystore_flash";


/*******************
 * Test cases
 *******************/

static void keystore_flash_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_not_block_aligned (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x11000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (NULL, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_init (&store, NULL, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_not_sector_aligned (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10001, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_no_keys (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, -1, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_NO_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_not_enough_space (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x1c000, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_INSUFFICIENT_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_decreasing_sectors (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_decreasing_sectors_not_block_aligned (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x11000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_decreasing_sectors_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (NULL, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_init_decreasing_sectors (&store, NULL, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 4, NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_decreasing_sectors_not_sector_aligned (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10001, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_decreasing_sectors_no_keys (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, -1, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_NO_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_init_decreasing_sectors_not_enough_space (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x3000, 4, &hash.base);
	CuAssertIntEquals (test, KEYSTORE_INSUFFICIENT_STORAGE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_release_null (CuTest *test)
{
	TEST_START;

	keystore_flash_release (NULL);
}

static void keystore_flash_test_save_key (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + RSA_PRIVKEY_DER_LEN,
		RSA_PRIVKEY_DER_HASH, RSA_PRIVKEY_DER_HASH_LEN);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_not_first_sector (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 3, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x13000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x13000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x13002, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0x13002 + RSA_PRIVKEY_DER_LEN,
		RSA_PRIVKEY_DER_HASH, RSA_PRIVKEY_DER_HASH_LEN);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 3, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_max_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint8_t key[4096 - 32 - 2];
	size_t key_len = sizeof (key);

	TEST_START;

	memset (key, 0x55, sizeof (key));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &key_len, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, key, sizeof (key));
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + sizeof (key), NULL,
		SHA256_HASH_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, key, key_len);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_decreasing_sectors (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + RSA_PRIVKEY_DER_LEN,
		RSA_PRIVKEY_DER_HASH, RSA_PRIVKEY_DER_HASH_LEN);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_decreasing_sectors_not_first_sector (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 3, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0xd000);
	status |= flash_master_mock_expect_write (&flash_mock, 0xd000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_write (&flash_mock, 0xd002, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_write (&flash_mock, 0xd002 + RSA_PRIVKEY_DER_LEN,
		RSA_PRIVKEY_DER_HASH, RSA_PRIVKEY_DER_HASH_LEN);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 3, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (NULL, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = store.base.save_key (&store.base, 0, NULL, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, (4096 - 32 - 2) + 1);
	CuAssertIntEquals (test, KEYSTORE_KEY_TOO_LONG, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_id_out_of_range (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 5, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_negative_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, -1, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG (RSA_PRIVKEY_DER), MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_test_save_key_erase_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_write_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_write_key_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_write_key_incomplete (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, RSA_PRIVKEY_DER, 254);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_write_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &RSA_PRIVKEY_DER_LEN,
		2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_save_key_write_hash_incomplete (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint8_t key[256 - 2 - 1];
	size_t key_len = sizeof (key);

	TEST_START;

	memset (key, 0x55, sizeof (key));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, (uint8_t*) &key_len, 2);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002, key, sizeof (key));
	status |= flash_master_mock_expect_write (&flash_mock, 0x10002 + sizeof (key), NULL, 1);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, key, key_len);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER_HASH,
		RSA_PRIVKEY_DER_HASH_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002 + RSA_PRIVKEY_DER_LEN, 0, -1, RSA_PRIVKEY_DER_HASH_LEN));

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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_not_first_sector (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 2, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x12000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0x12002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER_HASH,
		RSA_PRIVKEY_DER_HASH_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x12002 + RSA_PRIVKEY_DER_LEN, 0, -1, RSA_PRIVKEY_DER_HASH_LEN));

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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_decreasing_sectors (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER_HASH,
		RSA_PRIVKEY_DER_HASH_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002 + RSA_PRIVKEY_DER_LEN, 0, -1, RSA_PRIVKEY_DER_HASH_LEN));

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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_decreasing_sectors_not_first_sector (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 2, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0xe000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0xe002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER_HASH,
		RSA_PRIVKEY_DER_HASH_LEN,
		FLASH_EXP_READ_CMD (0x03, 0xe002 + RSA_PRIVKEY_DER_LEN, 0, -1, RSA_PRIVKEY_DER_HASH_LEN));

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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_id_out_of_range (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 5, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_negative_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, -1, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_hash_mismatch (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;
	uint8_t bad_hash[RSA_PRIVKEY_DER_HASH_LEN];

	TEST_START;

	memcpy (bad_hash, RSA_PRIVKEY_DER_HASH, RSA_PRIVKEY_DER_HASH_LEN);
	bad_hash[0] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, bad_hash, sizeof (bad_hash),
		FLASH_EXP_READ_CMD (0x03, 0x10002 + RSA_PRIVKEY_DER_LEN, 0, -1, RSA_PRIVKEY_DER_HASH_LEN));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_BAD_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_bad_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = (4096 - 32 - 2) + 1;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_read_key_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
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

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_read_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_load_key_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;
	uint16_t read_len = RSA_PRIVKEY_DER_LEN;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 2));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, FLASH_EXP_READ_CMD (0x03, 0x10002, 0, -1, RSA_PRIVKEY_DER_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_PRIVKEY_DER_HASH,
		RSA_PRIVKEY_DER_HASH_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10002 + RSA_PRIVKEY_DER_LEN, 0, -1, RSA_PRIVKEY_DER_HASH_LEN));

	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
}

static void keystore_flash_test_erase_key (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_not_first_sector (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x13000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_decreasing_sectors (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_decreasing_sectors_not_first_sector (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init_decreasing_sectors (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x0d000);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (NULL, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_id_out_of_range (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 5);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_negative_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, -1);
	CuAssertIntEquals (test, KEYSTORE_UNSUPPORTED_ID, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void keystore_flash_test_erase_key_erase_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash, 0x10000, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


CuSuite* get_keystore_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, keystore_flash_test_init);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_not_block_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_null);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_not_sector_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_no_keys);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_not_enough_space);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_decreasing_sectors);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_decreasing_sectors_not_block_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_decreasing_sectors_null);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_decreasing_sectors_not_sector_aligned);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_decreasing_sectors_no_keys);
	SUITE_ADD_TEST (suite, keystore_flash_test_init_decreasing_sectors_not_enough_space);
	SUITE_ADD_TEST (suite, keystore_flash_test_release_null);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_max_length);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_decreasing_sectors);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_decreasing_sectors_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_null);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_too_long);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_id_out_of_range);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_negative_id);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_hash_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_erase_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_write_length_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_write_key_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_write_key_incomplete);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_write_hash_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_save_key_write_hash_incomplete);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_decreasing_sectors);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_decreasing_sectors_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_null);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_id_out_of_range);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_negative_id);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_hash_mismatch);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_bad_length);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_read_length_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_read_key_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_read_hash_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_load_key_hash_error);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_decreasing_sectors);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_decreasing_sectors_not_first_sector);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_null);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_id_out_of_range);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_negative_id);
	SUITE_ADD_TEST (suite, keystore_flash_test_erase_key_erase_error);

	return suite;
}
