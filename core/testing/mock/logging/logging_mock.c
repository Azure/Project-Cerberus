// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "logging_mock.h"


static int logging_mock_create_entry (const struct logging *logging, uint8_t *entry, size_t length)
{
	struct logging_mock *mock = (struct logging_mock*) logging;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, logging_mock_create_entry, logging, MOCK_ARG_CALL (entry),
		MOCK_ARG_CALL (length));
}

static int logging_mock_flush (const struct logging *logging)
{
	struct logging_mock *mock = (struct logging_mock*) logging;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, logging_mock_flush, logging);
}

static int logging_mock_clear (const struct logging *logging)
{
	struct logging_mock *mock = (struct logging_mock*) logging;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, logging_mock_clear, logging);
}

static int logging_mock_get_size (const struct logging *logging)
{
	struct logging_mock *mock = (struct logging_mock*) logging;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, logging_mock_get_size, logging);
}

static int logging_mock_read_contents (const struct logging *logging, uint32_t offset,
	uint8_t *contents, size_t length)
{
	struct logging_mock *mock = (struct logging_mock*) logging;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, logging_mock_read_contents, logging, MOCK_ARG_CALL (offset),
		MOCK_ARG_CALL (contents), MOCK_ARG_CALL (length));
}

static int logging_mock_func_arg_count (void *func)
{
	if (func == logging_mock_read_contents) {
		return 3;
	}
	else if (func == logging_mock_create_entry) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* logging_mock_func_name_map (void *func)
{
	if (func == logging_mock_create_entry) {
		return "create_entry";
	}
	else if (func == logging_mock_flush) {
		return "flush";
	}
	else if (func == logging_mock_clear) {
		return "clear";
	}
	else if (func == logging_mock_get_size) {
		return "get_size";
	}
	else if (func == logging_mock_read_contents) {
		return "read_contents";
	}
	else {
		return "unknown";
	}
}

static const char* logging_mock_arg_name_map (void *func, int arg)
{
	if (func == logging_mock_create_entry) {
		switch (arg) {
			case 0:
				return "entry";

			case 1:
				return "length";
		}
	}
	else if (func == logging_mock_read_contents) {
		switch (arg) {
			case 0:
				return "offset";

			case 1:
				return "contents";

			case 2:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock interface for logging.
 *
 * @param mock The logging mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int logging_mock_init (struct logging_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct logging_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "logging");

	mock->base.create_entry = logging_mock_create_entry;
	mock->base.flush = logging_mock_flush;
	mock->base.clear = logging_mock_clear;
	mock->base.get_size = logging_mock_get_size;
	mock->base.read_contents = logging_mock_read_contents;

	mock->mock.func_arg_count = logging_mock_func_arg_count;
	mock->mock.func_name_map = logging_mock_func_name_map;
	mock->mock.arg_name_map = logging_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a logging mock.
 *
 * @param mock The mock to release.
 */
void logging_mock_release (struct logging_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int logging_mock_validate_and_release (struct logging_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		logging_mock_release (mock);
	}

	return status;
}
