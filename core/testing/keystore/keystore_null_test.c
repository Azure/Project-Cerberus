// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "keystore/keystore_null.h"
#include "keystore/keystore_null_static.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("keystore_null");


/*******************
 * Test cases
 *******************/

static void keystore_null_test_init (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);
	CuAssertPtrNotNull (test, store.base.erase_all_keys);

	keystore_null_release (&store);
}

static void keystore_null_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = keystore_null_init (NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);
}

static void keystore_null_test_static_init (CuTest *test)
{
	struct keystore_null store = keystore_null_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, store.base.save_key);
	CuAssertPtrNotNull (test, store.base.load_key);
	CuAssertPtrNotNull (test, store.base.erase_key);
	CuAssertPtrNotNull (test, store.base.erase_all_keys);

	keystore_null_release (&store);
}

static void keystore_null_test_release_null (CuTest *test)
{
	TEST_START;

	keystore_null_release (NULL);
}

static void keystore_null_test_save_key (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	keystore_null_release (&store);
}

static void keystore_null_test_save_key_static_init (CuTest *test)
{
	struct keystore_null store = keystore_null_static_init;
	int status;

	TEST_START;

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	keystore_null_release (&store);
}

static void keystore_null_test_save_key_null (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	status = store.base.save_key (NULL, 0, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = store.base.save_key (&store.base, 0, NULL, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	status = store.base.save_key (&store.base, 0, RSA_PRIVKEY_DER, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	keystore_null_release (&store);
}

static void keystore_null_test_load_key (CuTest *test)
{
	struct keystore_null store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	keystore_null_release (&store);
}

static void keystore_null_test_load_key_static_init (CuTest *test)
{
	struct keystore_null store = keystore_null_static_init;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	key = (uint8_t*) &key_len;
	status = store.base.load_key (&store.base, 0, &key, &key_len);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);
	CuAssertPtrEquals (test, NULL, key);

	keystore_null_release (&store);
}

static void keystore_null_test_load_key_null (CuTest *test)
{
	struct keystore_null store;
	int status;
	uint8_t *key = NULL;
	size_t key_len;

	TEST_START;

	status = keystore_null_init (&store);
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

	keystore_null_release (&store);
}

static void keystore_null_test_erase_key (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	keystore_null_release (&store);
}

static void keystore_null_test_erase_key_static_init (CuTest *test)
{
	struct keystore_null store = keystore_null_static_init;
	int status;

	TEST_START;

	status = store.base.erase_key (&store.base, 0);
	CuAssertIntEquals (test, 0, status);

	keystore_null_release (&store);
}

static void keystore_null_test_erase_key_null (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_key (NULL, 0);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	keystore_null_release (&store);
}

static void keystore_null_test_erase_all_keys (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_all_keys (&store.base);
	CuAssertIntEquals (test, 0, status);

	keystore_null_release (&store);
}

static void keystore_null_test_erase_all_keys_static_init (CuTest *test)
{
	struct keystore_null store = keystore_null_static_init;
	int status;

	TEST_START;

	status = store.base.erase_all_keys (&store.base);
	CuAssertIntEquals (test, 0, status);

	keystore_null_release (&store);
}

static void keystore_null_test_erase_all_keys_null (CuTest *test)
{
	struct keystore_null store;
	int status;

	TEST_START;

	status = keystore_null_init (&store);
	CuAssertIntEquals (test, 0, status);

	status = store.base.erase_all_keys (NULL);
	CuAssertIntEquals (test, KEYSTORE_INVALID_ARGUMENT, status);

	keystore_null_release (&store);
}


TEST_SUITE_START (keystore_null);

TEST (keystore_null_test_init);
TEST (keystore_null_test_init_null);
TEST (keystore_null_test_static_init);
TEST (keystore_null_test_release_null);
TEST (keystore_null_test_save_key);
TEST (keystore_null_test_save_key_static_init);
TEST (keystore_null_test_save_key_null);
TEST (keystore_null_test_load_key);
TEST (keystore_null_test_load_key_static_init);
TEST (keystore_null_test_load_key_null);
TEST (keystore_null_test_erase_key);
TEST (keystore_null_test_erase_key_static_init);
TEST (keystore_null_test_erase_key_null);
TEST (keystore_null_test_erase_all_keys);
TEST (keystore_null_test_erase_all_keys_static_init);
TEST (keystore_null_test_erase_all_keys_null);

TEST_SUITE_END;
