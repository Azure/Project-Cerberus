// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "spdm_protocol_session_observer_mock.h"
#include "cmd_interface/cmd_interface.h"


static void spdm_protocol_session_observer_mock_on_new_session (
	const struct spdm_protocol_session_observer *observer, uint32_t *session_id)
{
	struct spdm_protocol_session_observer_mock *mock =
		(struct spdm_protocol_session_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_session_observer_mock_on_new_session, observer,
		MOCK_ARG_PTR_CALL (session_id));
}

static void spdm_protocol_session_observer_mock_on_close_session (
	const struct spdm_protocol_session_observer *observer, uint32_t *session_id)
{
	struct spdm_protocol_session_observer_mock *mock =
		(struct spdm_protocol_session_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_session_observer_mock_on_close_session, observer,
		MOCK_ARG_PTR_CALL (session_id));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (spdm_protocol_session_observer, 2)
	MOCK_FUNCTION (
		spdm_protocol_session_observer,
		on_new_session,
		1,
		MOCK_FUNCTION_ARGS ("session_id"))
	MOCK_FUNCTION (
		spdm_protocol_session_observer,
		on_close_session,
		1,
		MOCK_FUNCTION_ARGS ("session_id"))
MOCK_FUNCTION_TABLE_END (spdm_protocol_session_observer)
// *INDENT-ON*

/**
 * Initialize a mock for receiving SPDM protocol session notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_protocol_session_observer_mock_init (struct spdm_protocol_session_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spdm_protocol_session_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_protocol_session_observer");

	mock->base.on_new_session = spdm_protocol_session_observer_mock_on_new_session;
	mock->base.on_close_session =
		spdm_protocol_session_observer_mock_on_close_session;

	MOCK_INTERFACE_INIT (mock->mock, spdm_protocol_session_observer);

	return 0;
}

/**
 * Release the resources used by a SPDM protocol session observer mock.
 *
 * @param mock The mock to release.
 */
void spdm_protocol_session_observer_mock_release (struct spdm_protocol_session_observer_mock *mock)
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
int spdm_protocol_session_observer_mock_validate_and_release (
	struct spdm_protocol_session_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spdm_protocol_session_observer_mock_release (mock);
	}

	return status;
}
