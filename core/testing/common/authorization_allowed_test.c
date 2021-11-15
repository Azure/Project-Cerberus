// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "common/authorization_allowed.h"


TEST_SUITE_LABEL ("authorization_allowed");


/*******************
 * Test cases
 *******************/

static void authorization_allowed_test_init (CuTest *test)
{
	struct authorization_allowed auth;
	int status;

	TEST_START;

	status = authorization_allowed_init (&auth);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.base.authorize);

	authorization_allowed_release (&auth);
}

static void authorization_allowed_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = authorization_allowed_init (NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
}

static void authorization_allowed_test_release_null (CuTest *test)
{
	TEST_START;

	authorization_allowed_release (NULL);
}

static void authorization_allowed_test_authorize (CuTest *test)
{
	struct authorization_allowed auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_allowed_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	authorization_allowed_release (&auth);
}

static void authorization_allowed_test_authorize_null (CuTest *test)
{
	struct authorization_allowed auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_allowed_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (NULL, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, NULL, &length);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, NULL);
	CuAssertIntEquals (test, 0, status);

	authorization_allowed_release (&auth);
}


TEST_SUITE_START (authorization_allowed);

TEST (authorization_allowed_test_init);
TEST (authorization_allowed_test_init_null);
TEST (authorization_allowed_test_release_null);
TEST (authorization_allowed_test_authorize);
TEST (authorization_allowed_test_authorize_null);

TEST_SUITE_END;
