// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform.h"
#include "status/rot_status.h"


TEST_SUITE_LABEL ("platform_semaphore");


/*******************
 * Test cases
 *******************/

static void platform_semaphore_test_init (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = platform_semaphore_init (NULL);
	CuAssertTrue (test, (status != 0));
}

static void platform_semaphore_test_free_null (CuTest *test)
{
	TEST_START;

	platform_semaphore_free (NULL);
}

static void platform_semaphore_test_post (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_post_null (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_post (NULL);
	CuAssertTrue (test, (status != 0));

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_wait (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_wait (&sem, 0);
	CuAssertIntEquals (test, 0, status);

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_wait_with_timeout (CuTest *test)
{
	platform_semaphore sem;
	platform_clock before;
	platform_clock after;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	platform_init_current_tick (&before);

	status = platform_semaphore_wait (&sem, 100);
	CuAssertIntEquals (test, 0, status);

	platform_init_current_tick (&after);
	CuAssertTrue (test, (platform_get_duration (&before, &after) < 100));

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_wait_with_timeout_no_post (CuTest *test)
{
	platform_semaphore sem;
	platform_clock before;
	platform_clock after;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	platform_init_current_tick (&before);

	status = platform_semaphore_wait (&sem, 100);
	CuAssertIntEquals (test, 1, status);

	platform_init_current_tick (&after);
	CuAssertTrue (test, (platform_get_duration (&before, &after) >= 100));

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_wait_null (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_wait (NULL, 0);
	CuAssertTrue (test, (status != 0));

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_try_wait (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (&sem);
	CuAssertIntEquals (test, 1, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (&sem);
	CuAssertIntEquals (test, 0, status);

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_try_wait_null (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (NULL);
	CuAssertTrue (test, (status != 0));

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_reset (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (&sem);
	CuAssertIntEquals (test, 1, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_reset (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (&sem);
	CuAssertIntEquals (test, 1, status);

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_reset_multiple_post (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (&sem);
	CuAssertIntEquals (test, 1, status);

	status = platform_semaphore_post (&sem);
	CuAssertIntEquals (test, 0, status);

	/* Some implementations may fail these calls due to binary semaphores. */
	platform_semaphore_post (&sem);
	platform_semaphore_post (&sem);

	status = platform_semaphore_reset (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_try_wait (&sem);
	CuAssertIntEquals (test, 1, status);

	platform_semaphore_free (&sem);
}

static void platform_semaphore_test_reset_null (CuTest *test)
{
	platform_semaphore sem;
	int status;

	TEST_START;

	status = platform_semaphore_init (&sem);
	CuAssertIntEquals (test, 0, status);

	status = platform_semaphore_reset (NULL);
	CuAssertTrue (test, (status != 0));

	platform_semaphore_free (&sem);
}


TEST_SUITE_START (platform_semaphore);

TEST (platform_semaphore_test_init);
TEST (platform_semaphore_test_init_null);
TEST (platform_semaphore_test_free_null);
TEST (platform_semaphore_test_post);
TEST (platform_semaphore_test_post_null);
TEST (platform_semaphore_test_wait);
TEST (platform_semaphore_test_wait_with_timeout);
TEST (platform_semaphore_test_wait_with_timeout_no_post);
TEST (platform_semaphore_test_wait_null);
TEST (platform_semaphore_test_try_wait);
TEST (platform_semaphore_test_try_wait_null);
TEST (platform_semaphore_test_reset);
TEST (platform_semaphore_test_reset_multiple_post);
TEST (platform_semaphore_test_reset_null);

TEST_SUITE_END;
