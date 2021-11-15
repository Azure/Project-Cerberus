// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_update_notification_mock.h"


static void firmware_update_notification_mock_state_change (
	struct firmware_update_notification *context, enum firmware_update_status state)
{
	struct firmware_update_notification_mock *mock =
		(struct firmware_update_notification_mock*) context;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, firmware_update_notification_mock_state_change, context,
		MOCK_ARG_CALL (state));
}

static int firmware_update_notification_mock_func_arg_count (void *func)
{
	if (func == firmware_update_notification_mock_state_change) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* firmware_update_notification_mock_func_name_map (void *func)
{
	if (func == firmware_update_notification_mock_state_change) {
		return "state_change";
	}
	else {
		return "unknown";
	}
}

static const char* firmware_update_notification_mock_arg_name_map (void *func, int arg)
{
	if (func == firmware_update_notification_mock_state_change) {
		switch (arg) {
			case 0:
				return "state";
		}
	}

	return "unknown";
}

/**
 * Initialize the mock handler for firmware update notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int firmware_update_notification_mock_init (struct firmware_update_notification_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct firmware_update_notification_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "firmware_update_notification");

	mock->base.status_change = firmware_update_notification_mock_state_change;

	mock->mock.func_arg_count = firmware_update_notification_mock_func_arg_count;
	mock->mock.func_name_map = firmware_update_notification_mock_func_name_map;
	mock->mock.arg_name_map = firmware_update_notification_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources for the mock notification handler.
 *
 * @param mock The mock to release.
 */
void firmware_update_notification_mock_release (struct firmware_update_notification_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify that the mock received the expected state notifications and release the mock.
 *
 * @param mock The mock to verify.
 *
 * @return 0 if all expected states were received or 1 if not.
 */
int firmware_update_notification_mock_validate_and_release (
	struct firmware_update_notification_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		firmware_update_notification_mock_release (mock);
	}

	return status;
}
