// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/authorized_data_token_only.h"
#include "common/authorized_data_token_only_static.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("authorized_data_token_only");


/*******************
 * Test cases
 *******************/

static void authorized_data_token_only_test_init (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.base.get_token_offset);
	CuAssertPtrNotNull (test, auth.base.get_authenticated_data);
	CuAssertPtrNotNull (test, auth.base.get_authenticated_data_length);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = authorized_data_token_only_init (NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);
}

static void authorized_data_token_only_test_static_init (CuTest *test)
{
	struct authorized_data_token_only auth = authorized_data_token_only_static_init ();

	TEST_START;

	CuAssertPtrNotNull (test, auth.base.get_token_offset);
	CuAssertPtrNotNull (test, auth.base.get_authenticated_data);
	CuAssertPtrNotNull (test, auth.base.get_authenticated_data_length);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_data_token_only_release (NULL);
}

static void authorized_data_token_only_test_get_token_offset (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	size_t offset = 0x55;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_token_offset (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &offset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, offset);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_token_offset_static_init (CuTest *test)
{
	struct authorized_data_token_only auth = authorized_data_token_only_static_init ();
	int status;
	size_t offset = 0x55;

	TEST_START;

	status = auth.base.get_token_offset (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &offset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, offset);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_token_offset_null (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	size_t offset = 0x55;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_token_offset (NULL, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &offset);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_token_offset (&auth.base, NULL, HASH_TESTING_FULL_BLOCK_512_LEN,
		&offset);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_token_offset (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_token_offset_no_auth_token (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	size_t offset = 0x55;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_token_offset (&auth.base, HASH_TESTING_FULL_BLOCK_512, 0, &offset);
	CuAssertIntEquals (test, AUTH_DATA_NO_AUTH_TOKEN, status);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_authenticated_data (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	const uint8_t *aad = HASH_TESTING_FULL_BLOCK_512;
	size_t aad_length = 0xaa;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_authenticated_data (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad, &aad_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, aad);
	CuAssertIntEquals (test, 0, aad_length);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_authenticated_data_static_init (CuTest *test)
{
	struct authorized_data_token_only auth = authorized_data_token_only_static_init ();
	int status;
	const uint8_t *aad = HASH_TESTING_FULL_BLOCK_512;
	size_t aad_length = 0xaa;

	TEST_START;

	status = auth.base.get_authenticated_data (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad, &aad_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, aad);
	CuAssertIntEquals (test, 0, aad_length);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_authenticated_data_null (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	const uint8_t *aad = HASH_TESTING_FULL_BLOCK_512;
	size_t aad_length = 0xaa;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_authenticated_data (NULL, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad, &aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data (&auth.base, NULL, HASH_TESTING_FULL_BLOCK_512_LEN,
		&aad, &aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data (&auth.base, HASH_TESTING_FULL_BLOCK_512, 0, &aad,
		&aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, NULL, &aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad, NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_authenticated_data_length (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	size_t aad_length = 0xaa;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_authenticated_data_length (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, aad_length);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_authenticated_data_length_static_init (CuTest *test)
{
	struct authorized_data_token_only auth = authorized_data_token_only_static_init ();
	int status;
	size_t aad_length = 0xaa;

	TEST_START;

	status = auth.base.get_authenticated_data_length (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, aad_length);

	authorized_data_token_only_release (&auth);
}

static void authorized_data_token_only_test_get_authenticated_data_length_null (CuTest *test)
{
	struct authorized_data_token_only auth;
	int status;
	size_t aad_length = 0xaa;

	TEST_START;

	status = authorized_data_token_only_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.get_authenticated_data_length (NULL, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data_length (&auth.base, NULL,
		HASH_TESTING_FULL_BLOCK_512_LEN, &aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data_length (&auth.base, HASH_TESTING_FULL_BLOCK_512, 0,
		&aad_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base.get_authenticated_data_length (&auth.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	authorized_data_token_only_release (&auth);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_data_token_only);

TEST (authorized_data_token_only_test_init);
TEST (authorized_data_token_only_test_init_null);
TEST (authorized_data_token_only_test_static_init);
TEST (authorized_data_token_only_test_release_null);
TEST (authorized_data_token_only_test_get_token_offset);
TEST (authorized_data_token_only_test_get_token_offset_static_init);
TEST (authorized_data_token_only_test_get_token_offset_null);
TEST (authorized_data_token_only_test_get_token_offset_no_auth_token);
TEST (authorized_data_token_only_test_get_authenticated_data);
TEST (authorized_data_token_only_test_get_authenticated_data_static_init);
TEST (authorized_data_token_only_test_get_authenticated_data_null);
TEST (authorized_data_token_only_test_get_authenticated_data_length);
TEST (authorized_data_token_only_test_get_authenticated_data_length_static_init);
TEST (authorized_data_token_only_test_get_authenticated_data_length_null);

TEST_SUITE_END;
// *INDENT-ON*
