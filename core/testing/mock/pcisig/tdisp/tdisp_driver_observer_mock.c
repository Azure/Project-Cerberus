// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "tdisp_driver_observer_mock.h"
#include "cmd_interface/cmd_interface.h"


static void tdisp_driver_observer_mock_on_start_interface (
	const struct tdisp_driver_observer *observer, uint32_t *function_index)
{
	struct tdisp_driver_observer_mock *mock =
		(struct tdisp_driver_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, tdisp_driver_observer_mock_on_start_interface, observer,
		MOCK_ARG_PTR_CALL (function_index));
}

static void tdisp_driver_observer_mock_on_stop_interface (
	const struct tdisp_driver_observer *observer, uint32_t *function_index)
{
	struct tdisp_driver_observer_mock *mock =
		(struct tdisp_driver_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, tdisp_driver_observer_mock_on_stop_interface, observer,
		MOCK_ARG_PTR_CALL (function_index));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (tdisp_driver_observer, 2)
	MOCK_FUNCTION (
		tdisp_driver_observer,
		on_start_interface,
		1,
		MOCK_FUNCTION_ARGS ("function_index"))
	MOCK_FUNCTION (
		tdisp_driver_observer,
		on_stop_interface,
		1,
		MOCK_FUNCTION_ARGS ("function_index"))
MOCK_FUNCTION_TABLE_END (tdisp_driver_observer)
// *INDENT-ON*

/**
 * Initialize a mock for receiving TDISP driver notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int tdisp_driver_observer_mock_init (struct tdisp_driver_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct tdisp_driver_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "tdisp_driver_observer");

	mock->base.on_start_interface = tdisp_driver_observer_mock_on_start_interface;
	mock->base.on_stop_interface =
		tdisp_driver_observer_mock_on_stop_interface;

	MOCK_INTERFACE_INIT (mock->mock, tdisp_driver_observer);

	return 0;
}

/**
 * Release the resources used by a TDISP driver observer mock.
 *
 * @param mock The mock to release.
 */
void tdisp_driver_observer_mock_release (struct tdisp_driver_observer_mock *mock)
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
int tdisp_driver_observer_mock_validate_and_release (
	struct tdisp_driver_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		tdisp_driver_observer_mock_release (mock);
	}

	return status;
}
