// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authorizing_signature_mock.h"


static int authorizing_signature_mock_get_signature (const struct authorizing_signature *auth,
	const uint8_t *data, size_t length, const uint8_t **signature, size_t *sig_length)
{
	struct authorizing_signature_mock *mock = (struct authorizing_signature_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, authorizing_signature_mock_get_signature, auth,
		MOCK_ARG_PTR_CALL (data), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (signature),
		MOCK_ARG_PTR_CALL (sig_length));
}

static int authorizing_signature_mock_get_signature_length (
	const struct authorizing_signature *auth, const uint8_t *data, size_t length,
	size_t *sig_length)
{
	struct authorizing_signature_mock *mock = (struct authorizing_signature_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, authorizing_signature_mock_get_signature_length, auth,
		MOCK_ARG_PTR_CALL (data), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (sig_length));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (authorizing_signature, 4)
	MOCK_FUNCTION (
		authorizing_signature,
		get_signature,
		4,
		MOCK_FUNCTION_ARGS ("data", "length", "signature", "sig_length"))
	MOCK_FUNCTION (
		authorizing_signature,
		get_signature_length,
		3,
		MOCK_FUNCTION_ARGS ("data", "length", "sig_length"))
MOCK_FUNCTION_TABLE_END (authorizing_signature)
// *INDENT-ON*

/**
 * Initialize a mock for handling authorizing signatures.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int authorizing_signature_mock_init (struct authorizing_signature_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct authorizing_signature_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "authorizing_signature");

	mock->base.get_signature = authorizing_signature_mock_get_signature;
	mock->base.get_signature_length = authorizing_signature_mock_get_signature_length;

	MOCK_INTERFACE_INIT (mock->mock, authorizing_signature);

	return 0;
}

/**
 * Release a mock authorized data handler.
 *
 * @param mock The mock to release.
 */
void authorizing_signature_mock_release (struct authorizing_signature_mock *mock)
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
int authorizing_signature_mock_validate_and_release (struct authorizing_signature_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		authorizing_signature_mock_release (mock);
	}

	return status;
}
