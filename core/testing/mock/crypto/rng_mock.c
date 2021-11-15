// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rng_mock.h"


static int rng_mock_generate_random_buffer (struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	struct rng_engine_mock *mock = (struct rng_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rng_mock_generate_random_buffer, engine, MOCK_ARG_CALL (rand_len),
		MOCK_ARG_CALL (buf));
}

static int rng_mock_func_arg_count (void *func)
{
	if (func == rng_mock_generate_random_buffer) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* rng_mock_func_name_map (void *func)
{
	if (func == rng_mock_generate_random_buffer) {
		return "generate_random_buffer";
	}
	else {
		return "unknown";
	}
}

static const char* rng_mock_arg_name_map (void *func, int arg)
{
	if (func == rng_mock_generate_random_buffer) {
		switch (arg) {
			case 0:
				return "rand_len";

			case 1:
				return "buf";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the RNG API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int rng_mock_init (struct rng_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct rng_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "rng");

	mock->base.generate_random_buffer = rng_mock_generate_random_buffer;

	mock->mock.func_arg_count = rng_mock_func_arg_count;
	mock->mock.func_name_map = rng_mock_func_name_map;
	mock->mock.arg_name_map = rng_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock RNG API instance.
 *
 * @param mock The mock to release.
 */
void rng_mock_release (struct rng_engine_mock *mock)
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
int rng_mock_validate_and_release (struct rng_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		rng_mock_release (mock);
	}

	return status;
}
