// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "shared_buffer_mock.h"


static int shared_buffer_mock_get_buffer_size (const struct shared_buffer_interface *buffer,
	size_t *size)
{
	struct shared_buffer_mock *mock = (struct shared_buffer_mock*) buffer;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, shared_buffer_mock_get_buffer_size, buffer, MOCK_ARG_PTR_CALL (size));
}

static int shared_buffer_mock_lock (const struct shared_buffer_interface *buffer,
	struct shared_buffer_handle *handle)
{
	struct shared_buffer_mock *mock = (struct shared_buffer_mock*) buffer;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, shared_buffer_mock_lock, buffer, MOCK_ARG_PTR_CALL (handle));
}

static int shared_buffer_mock_unlock (const struct shared_buffer_interface *buffer,
	struct shared_buffer_handle *handle)
{
	struct shared_buffer_mock *mock = (struct shared_buffer_mock*) buffer;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, shared_buffer_mock_unlock, buffer, MOCK_ARG_PTR_CALL (handle));
}

static int shared_buffer_mock_func_arg_count (void *func)
{
	if ((func == shared_buffer_mock_get_buffer_size) || (func == shared_buffer_mock_lock) ||
		(func == shared_buffer_mock_unlock)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* shared_buffer_mock_func_name_map (void *func)
{
	if (func == shared_buffer_mock_get_buffer_size) {
		return "get_buffer_size";
	}
	else if (func == shared_buffer_mock_lock) {
		return "lock";
	}
	else if (func == shared_buffer_mock_unlock) {
		return "unlock";
	}
	else {
		return "unknown";
	}
}

static const char* shared_buffer_mock_arg_name_map (void *func, int arg)
{
	if (func == shared_buffer_mock_get_buffer_size) {
		switch (arg) {
			case 0:
				return "size";
		}
	}
	else if (func == shared_buffer_mock_lock) {
		switch (arg) {
			case 0:
				return "handle";
		}
	}
	else if (func == shared_buffer_mock_unlock) {
		switch (arg) {
			case 0:
				return "handle";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for arbitrating access to a shared buffer.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int shared_buffer_mock_init (struct shared_buffer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct shared_buffer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "shared_buffer");

	mock->base.get_buffer_size = shared_buffer_mock_get_buffer_size;
	mock->base.lock = shared_buffer_mock_lock;
	mock->base.unlock = shared_buffer_mock_unlock;

	mock->mock.func_arg_count = shared_buffer_mock_func_arg_count;
	mock->mock.func_name_map = shared_buffer_mock_func_name_map;
	mock->mock.arg_name_map = shared_buffer_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock shared buffer instance.
 *
 * @param mock The mock to release.
 */
void shared_buffer_mock_release (struct shared_buffer_mock *mock)
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
int shared_buffer_mock_validate_and_release (struct shared_buffer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		shared_buffer_mock_release (mock);
	}

	return status;
}
