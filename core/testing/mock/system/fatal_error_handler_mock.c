// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fatal_error_handler_mock.h"


void fatal_error_handler_mock_unrecoverable_error (const struct fatal_error_handler *handler)
{
	struct fatal_error_handler_mock *mock = (struct fatal_error_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, fatal_error_handler_mock_unrecoverable_error, handler);
}

void fatal_error_handler_mock_panic (const struct fatal_error_handler *handler, int error_code,
	const struct debug_log_entry_info *error_log)
{
	struct fatal_error_handler_mock *mock = (struct fatal_error_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, fatal_error_handler_mock_panic, handler,
		MOCK_ARG_CALL (error_code), MOCK_ARG_PTR_CALL (error_log));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (fatal_error_handler, 2)
	MOCK_FUNCTION (
		fatal_error_handler,
		unrecoverable_error,
		0,
		MOCK_FUNCTION_ARGS (""))
	MOCK_FUNCTION (
		fatal_error_handler,
		panic,
		2,
		MOCK_FUNCTION_ARGS ("error_code", "error_log"))
MOCK_FUNCTION_TABLE_END (fatal_error_handler)
// *INDENT-ON*

/**
 * Initialize a mock for fatal error handling.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int fatal_error_handler_mock_init (struct fatal_error_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct fatal_error_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "fatal_error_handler");

	mock->base.unrecoverable_error = fatal_error_handler_mock_unrecoverable_error;
	mock->base.panic = fatal_error_handler_mock_panic;

	MOCK_INTERFACE_INIT (mock->mock, fatal_error_handler);

	return 0;
}

/**
 * Release the resources used by the mock.
 *
 * @param mock The mock to release.
 */
void fatal_error_handler_mock_release (struct fatal_error_handler_mock *mock)
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
int fatal_error_handler_mock_validate_and_release (struct fatal_error_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		fatal_error_handler_mock_release (mock);
	}

	return status;
}
