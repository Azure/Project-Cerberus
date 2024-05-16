// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/app_context_null.h"
#include "firmware/app_context_null_static.h"


TEST_SUITE_LABEL ("app_context_null");


/*******************
 * Test cases
 *******************/

static void app_context_null_test_init (CuTest *test)
{
	struct app_context_null context;
	int status;

	TEST_START;

	status = app_context_null_init (&context);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, context.base.save);

	app_context_null_release (&context);
}

static void app_context_null_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = app_context_null_init (NULL);
	CuAssertIntEquals (test, APP_CONTEXT_INVALID_ARGUMENT, status);
}

static void app_context_null_test_static_init (CuTest *test)
{
	struct app_context_null context = app_context_null_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, context.base.save);

	app_context_null_release (&context);
}

static void app_context_null_test_release_null (CuTest *test)
{
	TEST_START;

	app_context_null_release (NULL);
}

static void app_context_null_test_save (CuTest *test)
{
	struct app_context_null context;
	int status;

	TEST_START;

	status = app_context_null_init (&context);
	CuAssertIntEquals (test, 0, status);

	status = context.base.save (&context.base);
	CuAssertIntEquals (test, 0, status);

	app_context_null_release (&context);
}

static void app_context_null_test_save_static_init (CuTest *test)
{
	struct app_context_null context = app_context_null_static_init;
	int status;

	TEST_START;

	status = context.base.save (&context.base);
	CuAssertIntEquals (test, 0, status);

	app_context_null_release (&context);
}

static void app_context_null_test_save_null (CuTest *test)
{
	struct app_context_null context;
	int status;

	TEST_START;

	status = app_context_null_init (&context);
	CuAssertIntEquals (test, 0, status);

	status = context.base.save (NULL);
	CuAssertIntEquals (test, APP_CONTEXT_INVALID_ARGUMENT, status);

	app_context_null_release (&context);
}


// *INDENT-OFF*
TEST_SUITE_START (app_context_null);

TEST (app_context_null_test_init);
TEST (app_context_null_test_init_null);
TEST (app_context_null_test_static_init);
TEST (app_context_null_test_release_null);
TEST (app_context_null_test_save);
TEST (app_context_null_test_save_static_init);
TEST (app_context_null_test_save_null);

TEST_SUITE_END;
// *INDENT-ON*
