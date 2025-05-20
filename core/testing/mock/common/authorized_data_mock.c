// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authorized_data_mock.h"


static int authorized_data_mock_get_token_offset (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *token_offset)
{
	struct authorized_data_mock *mock = (struct authorized_data_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, authorized_data_mock_get_token_offset, auth, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (token_offset));
}

static int authorized_data_mock_get_authenticated_data (const struct authorized_data *auth,
	const uint8_t *data, size_t length, const uint8_t **aad, size_t *aad_length)
{
	struct authorized_data_mock *mock = (struct authorized_data_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, authorized_data_mock_get_authenticated_data, auth,
		MOCK_ARG_PTR_CALL (data), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (aad),
		MOCK_ARG_PTR_CALL (aad_length));
}

static int authorized_data_mock_get_authenticated_data_length (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *aad_length)
{
	struct authorized_data_mock *mock = (struct authorized_data_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, authorized_data_mock_get_authenticated_data_length, auth,
		MOCK_ARG_PTR_CALL (data), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (aad_length));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (authorized_data, 4)
	MOCK_FUNCTION (
		authorized_data,
		get_token_offset,
		3,
		MOCK_FUNCTION_ARGS ("data", "length", "token_offset"))
	MOCK_FUNCTION (
		authorized_data,
		get_authenticated_data,
		4,
		MOCK_FUNCTION_ARGS ("data", "length", "aad", "aad_length"))
	MOCK_FUNCTION (
		authorized_data,
		get_authenticated_data_length,
		3,
		MOCK_FUNCTION_ARGS ("data", "length", "aad_length"))
MOCK_FUNCTION_TABLE_END (authorized_data)
// *INDENT-ON*

/**
 * Initialize a mock for handling authorized data.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int authorized_data_mock_init (struct authorized_data_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct authorized_data_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "authorized_data");

	mock->base.get_token_offset = authorized_data_mock_get_token_offset;
	mock->base.get_authenticated_data = authorized_data_mock_get_authenticated_data;
	mock->base.get_authenticated_data_length = authorized_data_mock_get_authenticated_data_length;

	MOCK_INTERFACE_INIT (mock->mock, authorized_data);

	return 0;
}

/**
 * Release a mock authorized data handler.
 *
 * @param mock The mock to release.
 */
void authorized_data_mock_release (struct authorized_data_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int authorized_data_mock_validate_and_release (struct authorized_data_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		authorized_data_mock_release (mock);
	}

	return status;
}
