// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/authorization_disallowed.h"
#include "common/authorization_disallowed_static.h"


TEST_SUITE_LABEL ("authorization_disallowed");


/*******************
 * Test cases
 *******************/

static void authorization_disallowed_test_init (CuTest *test)
{
	struct authorization_disallowed auth;
	int status;

	TEST_START;

	status = authorization_disallowed_init (&auth);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.base.authorize);

	authorization_disallowed_release (&auth);
}

static void authorization_disallowed_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = authorization_disallowed_init (NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
}

static void authorization_disallowed_test_static_init (CuTest *test)
{
	struct authorization_disallowed auth = authorization_disallowed_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, auth.base.authorize);

	authorization_disallowed_release (&auth);
}

static void authorization_disallowed_test_release_null (CuTest *test)
{
	TEST_START;

	authorization_disallowed_release (NULL);
}

static void authorization_disallowed_test_authorize (CuTest *test)
{
	struct authorization_disallowed auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	status = authorization_disallowed_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	authorization_disallowed_release (&auth);
}

static void authorization_disallowed_test_authorize_static_init (CuTest *test)
{
	struct authorization_disallowed auth = authorization_disallowed_static_init;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	status = auth.base.authorize (&auth.base, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	authorization_disallowed_release (&auth);
}

static void authorization_disallowed_test_authorize_null (CuTest *test)
{
	struct authorization_disallowed auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	status = authorization_disallowed_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (NULL, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = auth.base.authorize (&auth.base, NULL, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = auth.base.authorize (&auth.base, &token, NULL);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	authorization_disallowed_release (&auth);
}


// *INDENT-OFF*
TEST_SUITE_START (authorization_disallowed);

TEST (authorization_disallowed_test_init);
TEST (authorization_disallowed_test_init_null);
TEST (authorization_disallowed_test_static_init);
TEST (authorization_disallowed_test_release_null);
TEST (authorization_disallowed_test_authorize);
TEST (authorization_disallowed_test_authorize_static_init);
TEST (authorization_disallowed_test_authorize_null);

TEST_SUITE_END;
// *INDENT-ON*
