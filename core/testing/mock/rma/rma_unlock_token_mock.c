// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "rma_unlock_token_mock.h"


static int rma_unlock_token_mock_authenticate (const struct rma_unlock_token *handler,
	const uint8_t *data, size_t length)
{
	struct rma_unlock_token_mock *mock = (struct rma_unlock_token_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rma_unlock_token_mock_authenticate, handler, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length));
}

static int rma_unlock_token_mock_func_arg_count (void *func)
{
	if (func == rma_unlock_token_mock_authenticate) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* rma_unlock_token_mock_func_name_map (void *func)
{
	if (func == rma_unlock_token_mock_authenticate) {
		return "authenticate";
	}
	else {
		return "unknown";
	}
}

static const char* rma_unlock_token_mock_arg_name_map (void *func, int arg)
{
	if (func == rma_unlock_token_mock_authenticate) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for handling RMA unlock tokens.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int rma_unlock_token_mock_init (struct rma_unlock_token_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct rma_unlock_token_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "rma_unlock_token");

	mock->base.authenticate = rma_unlock_token_mock_authenticate;

	mock->mock.func_arg_count = rma_unlock_token_mock_func_arg_count;
	mock->mock.func_name_map = rma_unlock_token_mock_func_name_map;
	mock->mock.arg_name_map = rma_unlock_token_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock RMA unlock token handler.
 *
 * @param mock The mock to release.
 */
void rma_unlock_token_mock_release (struct rma_unlock_token_mock *mock)
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
int rma_unlock_token_mock_validate_and_release (struct rma_unlock_token_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		rma_unlock_token_mock_release (mock);
	}

	return status;
}
