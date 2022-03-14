// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "keystore/keystore_flash.h"
#include "flash/flash_store.h"
#include "flash/flash_store_encrypted.h"
#include "flash/spi_flash.h"
#include "testing/mock/crypto/aes_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/flash/flash_store_mock.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/crypto/aes_testing.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("keystore_flash");


/*******************
 * Test cases
 *******************/

static void keystore_flash_test_init (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_init_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (NULL, &flash.base);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = keystore_flash_init (&store, NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void keystore_flash_test_release_null (CuTest *test)
{
	TEST_START;

	keystore_flash_release (NULL);
}

static void keystore_flash_test_save_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_save_key_not_first_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (3),
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 3, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_save_key_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (NULL, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_save_key_write_error (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash, RSA_PRIVKEY_DER_LEN,
		MOCK_ARG (0));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, RSA_PRIVKEY_DER_LEN, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_output (&flash.mock, 1, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, key_len);

	status = testing_validate_array (RSA_PRIVKEY_DER, key, key_len);
	CuAssertIntEquals (test, 0, status);

	platform_free (key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_not_first_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash, RSA_PRIVKEY_DER_LEN,
		MOCK_ARG (2));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, RSA_PRIVKEY_DER_LEN, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_output (&flash.mock, 1, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = store.base.load_key (&store.base, 2, &key, &key_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, key_len);

	status = testing_validate_array (RSA_PRIVKEY_DER, key, key_len);
	CuAssertIntEquals (test, 0, status);

	platform_free (key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_backwards_compatibility (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash spi;
	struct flash_store flash;
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

	status = spi_flash_init (&spi, &state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&spi, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&flash, &spi.base, 0x10000, 4, 0, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (struct flash_store_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (struct flash_store_header)));

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

	spi_flash_release (&spi);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	flash_store_release (&flash);
}

static void keystore_flash_test_load_key_backwards_compatibility_encrypted (CuTest *test)
{
	struct aes_engine_mock aes;
	struct rng_engine_mock rng;
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash spi;
	struct flash_store_encrypted flash;
	struct keystore_flash store;
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

	status = spi_flash_init (&spi, &state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&spi, 0x100000);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&flash, &spi.base, 0x10000, 4, 0,
		&aes.base, &rng.base);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (struct flash_store_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &read_len,
		sizeof (read_len),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (struct flash_store_header)));

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

	keystore_flash_release (&store);

	spi_flash_release (&spi);
	flash_store_encrypted_release (&flash);
}

static void keystore_flash_test_load_key_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
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

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_bad_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash, RSA_PRIVKEY_DER_LEN,
		MOCK_ARG (0));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_BAD_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_no_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash, FLASH_STORE_NO_DATA,
		MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_no_key_during_read (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash, RSA_PRIVKEY_DER_LEN,
		MOCK_ARG (0));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_read_length_error (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash,
		FLASH_STORE_GET_LENGTH_FAILED, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, FLASH_STORE_GET_LENGTH_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_load_key_read_key_error (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_data_length, &flash, RSA_PRIVKEY_DER_LEN,
		MOCK_ARG (0));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, FLASH_STORE_READ_FAILED, status);
	CuAssertPtrEquals (test, NULL, key);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.erase, &flash, 0, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_key_not_first_key (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.erase, &flash, 0, MOCK_ARG (4));
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 4);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_key_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (NULL, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_key_erase_error (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.erase, &flash, FLASH_STORE_ERASE_FAILED,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, FLASH_STORE_ERASE_FAILED, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_all_keys (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.erase_all, &flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_all_keys (&store.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_all_keys_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_all_keys (NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}

static void keystore_flash_test_erase_all_keys_erase_error (CuTest *test)
{
	struct flash_store_mock flash;
	struct keystore_flash store;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_flash_init (&store, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.erase_all, &flash, FLASH_STORE_ERASE_ALL_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_all_keys (&store.base);
	CuAssertIntEquals (test, FLASH_STORE_ERASE_ALL_FAILED, status);

	status = flash_store_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	keystore_flash_release (&store);
}


TEST_SUITE_START (keystore_flash);

TEST (keystore_flash_test_init);
TEST (keystore_flash_test_init_null);
TEST (keystore_flash_test_release_null);
TEST (keystore_flash_test_save_key);
TEST (keystore_flash_test_save_key_not_first_key);
TEST (keystore_flash_test_save_key_null);
TEST (keystore_flash_test_save_key_write_error);
TEST (keystore_flash_test_load_key);
TEST (keystore_flash_test_load_key_not_first_key);
TEST (keystore_flash_test_load_key_backwards_compatibility);
TEST (keystore_flash_test_load_key_backwards_compatibility_encrypted);
TEST (keystore_flash_test_load_key_null);
TEST (keystore_flash_test_load_key_bad_key);
TEST (keystore_flash_test_load_key_no_key);
TEST (keystore_flash_test_load_key_no_key_during_read);
TEST (keystore_flash_test_load_key_read_length_error);
TEST (keystore_flash_test_load_key_read_key_error);
TEST (keystore_flash_test_erase_key);
TEST (keystore_flash_test_erase_key_not_first_key);
TEST (keystore_flash_test_erase_key_null);
TEST (keystore_flash_test_erase_key_erase_error);
TEST (keystore_flash_test_erase_all_keys);
TEST (keystore_flash_test_erase_all_keys_null);
TEST (keystore_flash_test_erase_all_keys_erase_error);

TEST_SUITE_END;
