// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <memory.h>
#include "spdm_persistent_context_interface_mock.h"
#include "common/array_size.h"
#include "common/type_cast.h"


int spdm_persistent_context_interface_mock_get_responder_state (
	const struct spdm_persistent_context_interface *ctx, struct spdm_responder_state **state)
{
	struct spdm_persistent_context_interface_mock *mock = TO_DERIVED_TYPE (ctx,
		struct spdm_persistent_context_interface_mock, base);

	if (ctx == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_persistent_context_interface_mock_get_responder_state, ctx,
		MOCK_ARG_PTR_CALL (state));
}

int spdm_persistent_context_interface_mock_get_secure_session_manager_state (
	const struct spdm_persistent_context_interface *ctx,
	struct spdm_secure_session_manager_persistent_state **state)
{
	struct spdm_persistent_context_interface_mock *mock = TO_DERIVED_TYPE (ctx,
		struct spdm_persistent_context_interface_mock, base);

	if (ctx == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock,
		spdm_persistent_context_interface_mock_get_secure_session_manager_state, ctx,
		MOCK_ARG_PTR_CALL (state));
}

void spdm_persistent_context_interface_mock_unlock (
	const struct spdm_persistent_context_interface *ctx)
{
	struct spdm_persistent_context_interface_mock *mock = TO_DERIVED_TYPE (ctx,
		struct spdm_persistent_context_interface_mock, base);

	if (ctx == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, spdm_persistent_context_interface_mock_unlock, ctx);
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (spdm_persistent_context_interface, 2)
	MOCK_FUNCTION (
		spdm_persistent_context_interface,
		get_responder_state,
		1,
		MOCK_FUNCTION_ARGS ("state"))
	MOCK_FUNCTION (
		spdm_persistent_context_interface,
		get_secure_session_manager_state,
		1,
		MOCK_FUNCTION_ARGS ("state"))
	MOCK_FUNCTION (
		spdm_persistent_context_interface,
		unlock,
		0,
		MOCK_FUNCTION_ARGS ())
MOCK_FUNCTION_TABLE_END (spdm_persistent_context_interface)
// *INDENT-ON*

/**
 * Initialize a SPDM persistent context mock instance.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_persistent_context_interface_mock_init (
	struct spdm_persistent_context_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (*mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_persistent_context_interface_mock");

	mock->base.get_responder_state = spdm_persistent_context_interface_mock_get_responder_state;
	mock->base.get_secure_session_manager_state =
		spdm_persistent_context_interface_mock_get_secure_session_manager_state;
	mock->base.unlock = spdm_persistent_context_interface_mock_unlock;

	MOCK_INTERFACE_INIT (mock->mock, spdm_persistent_context_interface);

	return 0;
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int spdm_persistent_context_interface_mock_validate_and_release (
	struct spdm_persistent_context_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		mock_release (&mock->mock);
	}

	return status;
}
