// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "x509_extension_builder_mock.h"


static int x509_extension_builder_mock_build (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	struct x509_extension_builder_mock *mock = (struct x509_extension_builder_mock*) builder;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_extension_builder_mock_build, builder,
		MOCK_ARG_PTR_CALL (extension));
}

static void x509_extension_builder_mock_free (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	struct x509_extension_builder_mock *mock = (struct x509_extension_builder_mock*) builder;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, x509_extension_builder_mock_free, builder,
		MOCK_ARG_PTR_CALL (extension));
}

static int x509_extension_builder_mock_func_arg_count (void *func)
{
	if ((func == x509_extension_builder_mock_build) || (func == x509_extension_builder_mock_free)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* x509_extension_builder_mock_func_name_map (void *func)
{
	if (func == x509_extension_builder_mock_build) {
		return "build";
	}
	else if (func == x509_extension_builder_mock_free) {
		return "free";
	}
	else {
		return "unknown";
	}
}

static const char* x509_extension_builder_mock_arg_name_map (void *func, int arg)
{
	if (func == x509_extension_builder_mock_build) {
		switch (arg) {
			case 0:
				return "extension";
		}
	}
	else if (func == x509_extension_builder_mock_free) {
		switch (arg) {
			case 0:
				return "extension";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for building X.509 extensions.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int x509_extension_builder_mock_init (struct x509_extension_builder_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct x509_extension_builder_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "x509_extension_builder");

	mock->base.build = x509_extension_builder_mock_build;
	mock->base.free = x509_extension_builder_mock_free;

	mock->mock.func_arg_count = x509_extension_builder_mock_func_arg_count;
	mock->mock.func_name_map = x509_extension_builder_mock_func_name_map;
	mock->mock.arg_name_map = x509_extension_builder_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a extension builder mock.
 *
 * @param mock The mock to release.
 */
void x509_extension_builder_mock_release (struct x509_extension_builder_mock *mock)
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
int x509_extension_builder_mock_validate_and_release (struct x509_extension_builder_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		x509_extension_builder_mock_release (mock);
	}

	return status;
}
