// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ide_driver_observer_mock.h"
#include "cmd_interface/cmd_interface.h"


static void ide_driver_observer_mock_on_set_stop (
	const struct ide_driver_observer *observer, struct ide_driver_observer_key_set *key_set)
{
	struct ide_driver_observer_mock *mock =
		(struct ide_driver_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, ide_driver_observer_mock_on_set_stop, observer,
		MOCK_ARG_PTR_CALL (key_set));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (ide_driver_observer, 1)
	MOCK_FUNCTION (
		ide_driver_observer,
		on_set_stop,
		1,
		MOCK_FUNCTION_ARGS ("key_set"))
MOCK_FUNCTION_TABLE_END (ide_driver_observer)
// *INDENT-ON*

/**
 * Initialize a mock for receiving IDE driver notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int ide_driver_observer_mock_init (struct ide_driver_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ide_driver_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ide_driver_observer");

	mock->base.on_set_stop = ide_driver_observer_mock_on_set_stop;

	MOCK_INTERFACE_INIT (mock->mock, ide_driver_observer);

	return 0;
}

/**
 * Release the resources used by a IDE driver observer mock.
 *
 * @param mock The mock to release.
 */
void ide_driver_observer_mock_release (struct ide_driver_observer_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int ide_driver_observer_mock_validate_and_release (
	struct ide_driver_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ide_driver_observer_mock_release (mock);
	}

	return status;
}
