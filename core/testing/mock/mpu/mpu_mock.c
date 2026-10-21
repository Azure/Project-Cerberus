// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <memory.h>
#include "mpu_mock.h"
#include "common/type_cast.h"

int mpu_mock_get_page_size (const struct mpu_interface *mpu, size_t *page_size)
{
	struct mpu_mock *mock = TO_DERIVED_TYPE (mpu, struct mpu_mock, base);

	if ((mpu == NULL) || (page_size == NULL)) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mpu_mock_get_page_size, mpu, MOCK_ARG_PTR_CALL (page_size));
}

int mpu_mock_set_region_attributes (const struct mpu_interface *mpu, const void *region_address,
	size_t region_size, uint32_t protection_level, uint32_t page_attributes)
{
	struct mpu_mock *mock = TO_DERIVED_TYPE (mpu, struct mpu_mock, base);

	if (mpu == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mpu_mock_set_region_attributes, mpu,
		MOCK_ARG_PTR_CALL (region_address),	MOCK_ARG_CALL (region_size),
		MOCK_ARG_CALL (protection_level), MOCK_ARG_CALL (page_attributes));
}

int mpu_mock_get_page_attributes (const struct mpu_interface *mpu, const void *address,
	uint32_t protection_level, uint32_t *page_attributes)
{
	struct mpu_mock *mock = TO_DERIVED_TYPE (mpu, struct mpu_mock, base);

	if (mpu == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mpu_mock_get_page_attributes, mpu, MOCK_ARG_PTR_CALL (address),
		MOCK_ARG_CALL (protection_level), MOCK_ARG_PTR_CALL (page_attributes));
}

static int mpu_mock_func_arg_count (void *func)
{
	if (func == mpu_mock_get_page_size) {
		return 1;
	}
	else if (func == mpu_mock_set_region_attributes) {
		return 4;
	}
	else if (func == mpu_mock_get_page_attributes) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* mpu_mock_arg_name_map (void *func, int arg)
{
	if (func == mpu_mock_get_page_size) {
		switch (arg) {
			case 0:
				return "page_size";
		}
	}
	else if (func == mpu_mock_set_region_attributes) {
		switch (arg) {
			case 0:
				return "region_address";

			case 1:
				return "region_size";

			case 2:
				return "protection_level";

			case 3:
				return "page_attributes";
		}
	}
	else if (func == mpu_mock_get_page_attributes) {
		switch (arg) {
			case 0:
				return "address";

			case 1:
				return "protection_level";

			case 2:
				return "page_attributes";
		}
	}

	return "unknown";
}

static const char* mpu_mock_func_name_map (void *func)
{
	if (func == mpu_mock_get_page_size) {
		return "get_page_size";
	}
	else if (func == mpu_mock_set_region_attributes) {
		return "set_region_attributes";
	}
	else if (func == mpu_mock_get_page_attributes) {
		return "get_page_attributes";
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize a MPU mock instance.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int mpu_mock_init (struct mpu_mock *mock)
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

	mock_set_name (&mock->mock, "mpu");

	mock->base.get_page_size = mpu_mock_get_page_size;
	mock->base.set_region_attributes = mpu_mock_set_region_attributes;
	mock->base.get_page_attributes = mpu_mock_get_page_attributes;

	mock->mock.func_arg_count = mpu_mock_func_arg_count;
	mock->mock.func_name_map = mpu_mock_func_name_map;
	mock->mock.arg_name_map = mpu_mock_arg_name_map;

	return 0;
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int mpu_mock_validate_and_release (struct mpu_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		mock_release (&mock->mock);
	}

	return status;
}
