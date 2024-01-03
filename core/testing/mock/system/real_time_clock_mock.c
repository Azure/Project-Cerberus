// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "real_time_clock_mock.h"


static int real_time_clock_mock_get_time (const struct real_time_clock *rtc, uint64_t *msec)
{
	struct real_time_clock_mock *mock = (struct real_time_clock_mock*) rtc;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, real_time_clock_mock_get_time, rtc, MOCK_ARG_PTR_CALL (msec));
}

static int real_time_clock_mock_set_time (const struct real_time_clock *rtc, uint64_t msec)
{
	struct real_time_clock_mock *mock = (struct real_time_clock_mock*) rtc;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, real_time_clock_mock_set_time, rtc, MOCK_ARG_CALL (msec));
}

static int real_time_clock_mock_func_arg_count (void *func)
{
	if ((func == real_time_clock_mock_get_time) || (func == real_time_clock_mock_set_time)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* real_time_clock_mock_func_name_map (void *func)
{
	if (func == real_time_clock_mock_get_time) {
		return "get_time";
	}
	else if (func == real_time_clock_mock_set_time) {
		return "set_time";
	}
	else {
		return "unknown";
	}
}

static const char* real_time_clock_mock_arg_name_map (void *func, int arg)
{
	if ((func == real_time_clock_mock_get_time) || (func == real_time_clock_mock_set_time)) {
		switch (arg) {
			case 0:
				return "msec";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a real time clock interface.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int real_time_clock_mock_init (struct real_time_clock_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct real_time_clock_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "real_time_clock");

	mock->base.get_time = real_time_clock_mock_get_time;
	mock->base.set_time = real_time_clock_mock_set_time;

	mock->mock.func_arg_count = real_time_clock_mock_func_arg_count;
	mock->mock.func_name_map = real_time_clock_mock_func_name_map;
	mock->mock.arg_name_map = real_time_clock_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a real time clock instance.
 *
 * @param mock The mock to release.
 */
void real_time_clock_mock_release (struct real_time_clock_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the mock was called as expected and release the instance.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int real_time_clock_mock_validate_and_release (struct real_time_clock_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		real_time_clock_mock_release (mock);
	}

	return status;
}
