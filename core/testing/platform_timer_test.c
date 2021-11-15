// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform.h"
#include "status/rot_status.h"


TEST_SUITE_LABEL ("platform_timer");


/**
 * Test context for testing timer callbacks.
 */
struct timer_context {
	int val;
	int sleep;
	platform_timer *timer;
};

/**
 * Test timer notification function.
 *
 * @param context The timer context.
 */
static void platform_timer_testing_callback (void *context)
{
	struct timer_context *ctxt = (struct timer_context*) context;

	if (ctxt->timer) {
		platform_timer_disarm (ctxt->timer);
	}

	ctxt->val++;

	if (ctxt->sleep) {
		platform_msleep (ctxt->sleep);
		ctxt->val++;
	}
}


/*******************
 * Test cases
 *******************/

static void platform_timer_test_create (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	platform_timer_delete (&timer);
}

static void platform_timer_test_create_null (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (NULL, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, 0), status & 0xffffff00);

	status = platform_timer_create (&timer, NULL, &context);
	CuAssertIntEquals (test, ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, 0), status & 0xffffff00);
}

static void platform_timer_test_delete_null (CuTest *test)
{
	TEST_START;

	platform_timer_delete (NULL);
}

static void platform_timer_test_arm_one_shot (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (400);
	CuAssertIntEquals (test, 1, context.val);

	platform_timer_delete (&timer);
}

static void platform_timer_test_arm_one_shot_reset_timeout (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);
	CuAssertIntEquals (test, 0, context.val);

	status = platform_timer_arm_one_shot (&timer, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (600);
	CuAssertIntEquals (test, 1, context.val);

	platform_timer_delete (&timer);
}

static void platform_timer_test_arm_one_shot_change_timeout (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);
	CuAssertIntEquals (test, 0, context.val);

	status = platform_timer_arm_one_shot (&timer, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (200);
	CuAssertIntEquals (test, 1, context.val);

	platform_timer_delete (&timer);
}

static void platform_timer_test_arm_one_shot_null (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (NULL, 100);
	CuAssertIntEquals (test, ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, 0), status & 0xffffff00);

	status = platform_timer_arm_one_shot (&timer, 0);
	CuAssertIntEquals (test, ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, 0), status & 0xffffff00);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);
	CuAssertIntEquals (test, 0, context.val);

	status = platform_timer_disarm (&timer);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (500);
	CuAssertIntEquals (test, 0, context.val);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm_not_active (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_disarm (&timer);
	CuAssertIntEquals (test, 0, status);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm_after_expiration (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (400);
	CuAssertIntEquals (test, 1, context.val);

	status = platform_timer_disarm (&timer);
	CuAssertIntEquals (test, 0, status);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm_twice (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);
	CuAssertIntEquals (test, 0, context.val);

	status = platform_timer_disarm (&timer);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_disarm (&timer);
	CuAssertIntEquals (test, 0, status);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm_callback_active (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	context.sleep = 500;

	status = platform_timer_arm_one_shot (&timer, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (200);
	CuAssertIntEquals (test, 1, context.val);

	status = platform_timer_disarm (&timer);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2, context.val);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm_from_callback (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	context.timer = &timer;

	status = platform_timer_arm_one_shot (&timer, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (400);
	CuAssertIntEquals (test, 1, context.val);

	platform_timer_delete (&timer);
}

static void platform_timer_test_disarm_null (CuTest *test)
{
	int status;

	TEST_START;

	status = platform_timer_disarm (NULL);
	CuAssertIntEquals (test, ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, 0), status & 0xffffff00);
}

static void platform_timer_test_delete_active_timer (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	status = platform_timer_arm_one_shot (&timer, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);
	CuAssertIntEquals (test, 0, context.val);

	platform_timer_delete (&timer);

	platform_msleep (500);
	CuAssertIntEquals (test, 0, context.val);
}

static void platform_timer_test_delete_callback_active (CuTest *test)
{
	platform_timer timer;
	struct timer_context context;
	int status;

	TEST_START;

	memset (&context, 0, sizeof (context));

	status = platform_timer_create (&timer, platform_timer_testing_callback, &context);
	CuAssertIntEquals (test, 0, status);

	context.sleep = 500;

	status = platform_timer_arm_one_shot (&timer, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (200);
	CuAssertIntEquals (test, 1, context.val);

	platform_timer_delete (&timer);

	CuAssertIntEquals (test, 2, context.val);
}


TEST_SUITE_START (platform_timer);

TEST (platform_timer_test_create);
TEST (platform_timer_test_create_null);
TEST (platform_timer_test_delete_null);
TEST (platform_timer_test_arm_one_shot);
TEST (platform_timer_test_arm_one_shot_reset_timeout);
TEST (platform_timer_test_arm_one_shot_change_timeout);
TEST (platform_timer_test_arm_one_shot_null);
TEST (platform_timer_test_disarm);
TEST (platform_timer_test_disarm_not_active);
TEST (platform_timer_test_disarm_after_expiration);
TEST (platform_timer_test_disarm_twice);
TEST (platform_timer_test_disarm_callback_active);
TEST (platform_timer_test_disarm_from_callback);
TEST (platform_timer_test_disarm_null);
TEST (platform_timer_test_delete_active_timer);
TEST (platform_timer_test_delete_callback_active);

TEST_SUITE_END;
