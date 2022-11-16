// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform_api.h"
#include "status/rot_status.h"


TEST_SUITE_LABEL ("platform_clock");


/*******************
 * Test cases
 *******************/

static void platform_clock_test_init_timeout (CuTest *test)
{
	platform_clock timeout;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_timeout (500, &timeout);
	CuAssertIntEquals (test, 0, status);

	status = platform_get_timeout_remaining (&timeout, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 500));
	CuAssertTrue (test, (msec > 450));	/* Allow for some variance in processing time. */

	status = platform_has_timeout_expired (&timeout);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (510);

	status = platform_get_timeout_remaining (&timeout, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, msec);

	status = platform_has_timeout_expired (&timeout);
	CuAssertIntEquals (test, 1, status);
}

static void platform_clock_test_init_timeout_null (CuTest *test)
{
	int status;

	TEST_START;

	status = platform_init_timeout (500, NULL);
	CuAssertIntEquals (test, ROT_MODULE_PLATFORM_TIMEOUT, ROT_GET_MODULE (status));
}

static void platform_clock_test_increase_timeout (CuTest *test)
{
	platform_clock timeout;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_timeout (500, &timeout);
	CuAssertIntEquals (test, 0, status);

	status = platform_get_timeout_remaining (&timeout, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 500));
	CuAssertTrue (test, (msec > 450));	/* Allow for some variance in processing time. */

	status = platform_increase_timeout (1000, &timeout);
	CuAssertIntEquals (test, 0, status);

	status = platform_get_timeout_remaining (&timeout, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1500));
	CuAssertTrue (test, (msec > 1400));	/* Allow for some variance in processing time. */

	status = platform_has_timeout_expired (&timeout);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (510);

	status = platform_get_timeout_remaining (&timeout, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 990));
	CuAssertTrue (test, (msec > 800));	/* Allow for some variance in processing time. */

	status = platform_has_timeout_expired (&timeout);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (1000);

	status = platform_get_timeout_remaining (&timeout, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, msec);

	status = platform_has_timeout_expired (&timeout);
	CuAssertIntEquals (test, 1, status);
}

static void platform_clock_test_increase_timeout_null (CuTest *test)
{
	int status;

	TEST_START;

	status = platform_increase_timeout (500, NULL);
	CuAssertIntEquals (test, ROT_MODULE_PLATFORM_TIMEOUT, ROT_GET_MODULE (status));
}

static void platform_clock_test_has_timeout_expired_null (CuTest *test)
{
	int status;

	TEST_START;

	status = platform_has_timeout_expired (NULL);
	CuAssertIntEquals (test, ROT_MODULE_PLATFORM_TIMEOUT, ROT_GET_MODULE (status));
}

static void platform_clock_test_get_timeout_remaining_null (CuTest *test)
{
	platform_clock timeout;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_get_timeout_remaining (NULL, &msec);
	CuAssertIntEquals (test, ROT_MODULE_PLATFORM_TIMEOUT, ROT_GET_MODULE (status));

	status = platform_get_timeout_remaining (&timeout, NULL);
	CuAssertIntEquals (test, ROT_MODULE_PLATFORM_TIMEOUT, ROT_GET_MODULE (status));
}

static void platform_clock_test_get_duration (CuTest *test)
{
	platform_clock start;
	platform_clock end;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_current_tick (&start);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (500);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);

	msec = platform_get_duration (&start, &end);
	CuAssertTrue (test, (msec >= 500));
	CuAssertTrue (test, (msec < 550));	/* There shouldn't be much else going on, so bound this for testing. */
}

static void platform_clock_test_get_duration_of_expired_timeout (CuTest *test)
{
	platform_clock timeout;
	platform_clock end;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_timeout (200, &timeout);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (500);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);

	status = platform_has_timeout_expired (&timeout);
	CuAssertIntEquals (test, 1, status);

	msec = platform_get_duration (&timeout, &end);
	CuAssertTrue (test, (msec >= 300));
	CuAssertTrue (test, (msec < 350));	/* There shouldn't be much else going on, so bound this for testing. */
}

static void platform_clock_test_get_duration_between_two_timeouts_less_than_one_second (
	CuTest *test)
{
	platform_clock timeout1;
	platform_clock timeout2;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_timeout (200, &timeout1);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (600, &timeout2);
	CuAssertIntEquals (test, 0, status);

	msec = platform_get_duration (&timeout1, &timeout2);
	CuAssertIntEquals (test, 400, msec);
}

static void platform_clock_test_get_duration_between_two_timeouts_one_second (CuTest *test)
{
	platform_clock timeout1;
	platform_clock timeout2;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_timeout (200, &timeout1);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (1300, &timeout2);
	CuAssertIntEquals (test, 0, status);

	msec = platform_get_duration (&timeout1, &timeout2);
	CuAssertIntEquals (test, 1100, msec);
}

static void platform_clock_test_get_duration_between_two_timeouts_more_than_one_second (
	CuTest *test)
{
	platform_clock timeout1;
	platform_clock timeout2;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_timeout (200, &timeout1);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (3900, &timeout2);
	CuAssertIntEquals (test, 0, status);

	msec = platform_get_duration (&timeout1, &timeout2);
	CuAssertIntEquals (test, 3700, msec);
}

static void platform_clock_test_get_duration_null (CuTest *test)
{
	platform_clock start;
	platform_clock end;
	uint32_t msec;
	int status;

	TEST_START;

	status = platform_init_current_tick (&start);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);

	msec = platform_get_duration (NULL, &end);
	CuAssertIntEquals (test, 0, msec);

	msec = platform_get_duration (&start, NULL);
	CuAssertIntEquals (test, 0, msec);
}

static void platform_clock_test_init_current_tick_null (CuTest *test)
{
	int status;

	TEST_START;

	status = platform_init_current_tick (NULL);
	CuAssertIntEquals (test, ROT_MODULE_PLATFORM_TIMEOUT, ROT_GET_MODULE (status));
}

static void platform_clock_test_get_time (CuTest *test)
{
	uint64_t start;
	uint64_t end;
	uint64_t diff;

	TEST_START;

	start = platform_get_time ();
	CuAssertTrue (test, (start != 0));

	platform_msleep (300);

	end = platform_get_time ();
	CuAssertTrue (test, (start != 0));

	diff = end - start;
	CuAssertTrue (test, (diff >= 300));
	CuAssertTrue (test, (diff < 350));	/* There shouldn't be much else going on, so bound this for testing. */
}


TEST_SUITE_START (platform_clock);

TEST (platform_clock_test_init_timeout);
TEST (platform_clock_test_init_timeout_null);
TEST (platform_clock_test_increase_timeout);
TEST (platform_clock_test_increase_timeout_null);
TEST (platform_clock_test_has_timeout_expired_null);
TEST (platform_clock_test_get_timeout_remaining_null);
TEST (platform_clock_test_get_duration);
TEST (platform_clock_test_get_duration_of_expired_timeout);
TEST (platform_clock_test_get_duration_between_two_timeouts_less_than_one_second);
TEST (platform_clock_test_get_duration_between_two_timeouts_one_second);
TEST (platform_clock_test_get_duration_between_two_timeouts_more_than_one_second);
TEST (platform_clock_test_get_duration_null);
TEST (platform_clock_test_init_current_tick_null);
TEST (platform_clock_test_get_time);

TEST_SUITE_END;
