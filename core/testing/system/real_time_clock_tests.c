// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "common/unused.h"
#include "system/real_time_clock_static.h"
#include "testing/mock/system/real_time_clock_mock.h"


TEST_SUITE_LABEL ("real_time_clock");


static int real_time_clock_get_time_empty (const struct real_time_clock *rtc, uint64_t *msec)
{
	UNUSED (rtc);
	UNUSED (msec);

	return 0;
}


/*******************
 * Test cases
 *******************/

static void real_time_clock_test_init_static (CuTest *test)
{
	const struct real_time_clock rtc = real_time_clock_static_init (real_time_clock_get_time_empty,
		real_time_clock_set_time_unsupported);

	TEST_START;

	CuAssertPtrEquals (test, rtc.get_time, real_time_clock_get_time_empty);
	CuAssertPtrEquals (test, rtc.set_time, real_time_clock_set_time_unsupported);
}

static void real_time_clock_test_set_time_unsupported (CuTest *test)
{
	const struct real_time_clock rtc = real_time_clock_static_init (real_time_clock_get_time_empty,
		real_time_clock_set_time_unsupported);
	int status;

	TEST_START;

	status = rtc.set_time (&rtc, 0);
	CuAssertIntEquals (test, REAL_TIME_CLOCK_UNSUPPORTED, status);
}

static void real_time_clock_test_set_time_unsupported_null (CuTest *test)
{
	int status;

	TEST_START;

	status = real_time_clock_set_time_unsupported (NULL, 0);
	CuAssertIntEquals (test, REAL_TIME_CLOCK_INVALID_ARGUMENT, status);
}


TEST_SUITE_START (real_time_clock);

TEST (real_time_clock_test_init_static);
TEST (real_time_clock_test_set_time_unsupported);
TEST (real_time_clock_test_set_time_unsupported_null);

TEST_SUITE_END;
