// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "platform_api.h"
#include "common/unused.h"
#include "system/real_time_clock_linux_static.h"


TEST_SUITE_LABEL ("real_time_clock_linux");


/*******************
 * Test cases
 *******************/

static void real_time_clock_linux_test_init (CuTest *test)
{
	struct real_time_clock_linux rtc;
	int status;

	TEST_START;

	status = real_time_clock_linux_init (&rtc);
	CuAssertIntEquals (test, 0, status);

	real_time_clock_linux_release (&rtc);
}

static void real_time_clock_linux_test_static_init (CuTest *test)
{
	const struct real_time_clock_linux rtc = real_time_clock_linux_static_init ();

	TEST_START;

	real_time_clock_linux_release (&rtc);
}

static void real_time_clock_linux_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = real_time_clock_linux_init (NULL);
	CuAssertIntEquals (test, REAL_TIME_CLOCK_INVALID_ARGUMENT, status);
}

static void real_time_clock_linux_test_release_null (CuTest *test)
{
	TEST_START;

	real_time_clock_linux_release (NULL);
}

static void real_time_clock_linux_test_get_time (CuTest *test)
{
	struct real_time_clock_linux rtc;
	uint64_t start = 0;
	uint64_t end = 0;
	uint64_t diff;
	int status;

	TEST_START;

	status = real_time_clock_linux_init (&rtc);
	CuAssertIntEquals (test, 0, status);

	status = rtc.base.get_time (&rtc.base, &start);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (300);

	status = rtc.base.get_time (&rtc.base, &end);
	CuAssertIntEquals (test, 0, status);

	real_time_clock_linux_release (&rtc);

	diff = end - start;
	CuAssertTrue (test, (diff >= 300));
	/* There shouldn't be much else going on, so bound this for testing. */
	CuAssertTrue (test, (diff < 350));
}

static void real_time_clock_linux_test_get_time_static (CuTest *test)
{
	const struct real_time_clock_linux rtc = real_time_clock_linux_static_init ();
	uint64_t start = 0;
	uint64_t end = 0;
	uint64_t diff;
	int status;

	TEST_START;

	status = rtc.base.get_time (&rtc.base, &start);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (300);

	status = rtc.base.get_time (&rtc.base, &end);
	CuAssertIntEquals (test, 0, status);

	diff = end - start;
	CuAssertTrue (test, (diff >= 300));
	/* There shouldn't be much else going on, so bound this for testing. */
	CuAssertTrue (test, (diff < 350));
}

static void real_time_clock_linux_test_get_time_null (CuTest *test)
{
	struct real_time_clock_linux rtc;
	uint64_t timestamp;
	int status;

	TEST_START;

	status = real_time_clock_linux_init (&rtc);
	CuAssertIntEquals (test, 0, status);

	status = rtc.base.get_time (&rtc.base, NULL);
	CuAssertIntEquals (test, REAL_TIME_CLOCK_INVALID_ARGUMENT, status);

	status = rtc.base.get_time (NULL, &timestamp);
	CuAssertIntEquals (test, REAL_TIME_CLOCK_INVALID_ARGUMENT, status);

	real_time_clock_linux_release (&rtc);
}

static void real_time_clock_linux_test_set_time_null (CuTest *test)
{
	struct real_time_clock_linux rtc;
	int status;

	TEST_START;

	status = real_time_clock_linux_init (&rtc);
	CuAssertIntEquals (test, 0, status);

	status = rtc.base.set_time (NULL, 0);
	CuAssertIntEquals (test, REAL_TIME_CLOCK_INVALID_ARGUMENT, status);

	real_time_clock_linux_release (&rtc);
}


TEST_SUITE_START (real_time_clock_linux);

TEST (real_time_clock_linux_test_init);
TEST (real_time_clock_linux_test_static_init);
TEST (real_time_clock_linux_test_init_null);
TEST (real_time_clock_linux_test_release_null);
TEST (real_time_clock_linux_test_get_time);
TEST (real_time_clock_linux_test_get_time_static);
TEST (real_time_clock_linux_test_get_time_null);
TEST (real_time_clock_linux_test_set_time_null);

TEST_SUITE_END;