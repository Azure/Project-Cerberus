// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <memory.h>
#include "mmio_register_block_mock.h"
#include "common/type_cast.h"


int mmio_register_block_mock_map (const struct mmio_register_block *register_block)
{
	struct mmio_register_block_mock *mock = TO_DERIVED_TYPE (register_block,
		struct mmio_register_block_mock, base);

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, mmio_register_block_mock_map, register_block);
}

void mmio_register_block_mock_unmap (const struct mmio_register_block *register_block)
{
	struct mmio_register_block_mock *mock = TO_DERIVED_TYPE (register_block,
		struct mmio_register_block_mock, base);

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, mmio_register_block_mock_unmap, register_block);
}

int mmio_register_block_mock_read32 (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint32_t *dest)
{
	struct mmio_register_block_mock *mock = TO_DERIVED_TYPE (register_block,
		struct mmio_register_block_mock, base);

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mmio_register_block_mock_read32, register_block,
		MOCK_ARG_CALL (register_offset), MOCK_ARG_PTR_CALL (dest));
}

int mmio_register_block_mock_write32 (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint32_t value)
{
	struct mmio_register_block_mock *mock = TO_DERIVED_TYPE (register_block,
		struct mmio_register_block_mock, base);

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mmio_register_block_mock_write32, register_block,
		MOCK_ARG_CALL (register_offset), MOCK_ARG_CALL (value));
}

int mmio_register_block_mock_block_read32 (const struct mmio_register_block *register_block,
	uintptr_t block_offset, uint32_t *dest, size_t dwords_count)
{
	struct mmio_register_block_mock *mock = TO_DERIVED_TYPE (register_block,
		struct mmio_register_block_mock, base);

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mmio_register_block_mock_block_read32, register_block,
		MOCK_ARG_CALL (block_offset), MOCK_ARG_PTR_CALL (dest), MOCK_ARG_CALL (dwords_count));
}

int mmio_register_block_mock_block_write32 (const struct mmio_register_block *register_block,
	uintptr_t block_offset, const uint32_t *src, size_t dwords_count)
{
	struct mmio_register_block_mock *mock = TO_DERIVED_TYPE (register_block,
		struct mmio_register_block_mock, base);

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mmio_register_block_mock_block_write32, register_block,
		MOCK_ARG_CALL (block_offset), MOCK_ARG_PTR_CALL (src), MOCK_ARG_CALL (dwords_count));
}

static int mmio_register_block_mock_func_arg_count (void *func)
{
	if (func == mmio_register_block_mock_map) {
		return 0;
	}
	else if (func == mmio_register_block_mock_unmap) {
		return 0;
	}
	else if (func == mmio_register_block_mock_read32) {
		return 2;
	}
	else if (func == mmio_register_block_mock_write32) {
		return 2;
	}
	else if (func == mmio_register_block_mock_block_read32) {
		return 3;
	}
	else if (func == mmio_register_block_mock_block_write32) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* mmio_register_block_mock_arg_name_map (void *func, int arg)
{
	if (func == mmio_register_block_mock_read32) {
		switch (arg) {
			case 0:
				return "register_offset";

			case 1:
				return "dest";
		}
	}
	else if (func == mmio_register_block_mock_write32) {
		switch (arg) {
			case 0:
				return "register_offset";

			case 1:
				return "value";
		}
	}
	else if (func == mmio_register_block_mock_block_read32) {
		switch (arg) {
			case 0:
				return "block_offset";

			case 1:
				return "dest";

			case 2:
				return "dwords_count";
		}
	}
	else if (func == mmio_register_block_mock_block_write32) {
		switch (arg) {
			case 0:
				return "block_offset";

			case 1:
				return "src";

			case 2:
				return "dwords_count";
		}
	}

	return "unknown";
}

static const char* mmio_register_block_mock_func_name_map (void *func)
{
	if (func == mmio_register_block_mock_map) {
		return "map";
	}
	else if (func == mmio_register_block_mock_unmap) {
		return "unmap";
	}
	else if (func == mmio_register_block_mock_read32) {
		return "read32";
	}
	else if (func == mmio_register_block_mock_write32) {
		return "write32";
	}
	else if (func == mmio_register_block_mock_block_read32) {
		return "block_read32";
	}
	else if (func == mmio_register_block_mock_block_write32) {
		return "block_write32";
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize a mock MMIO register block instance.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int mmio_register_block_mock_init (struct mmio_register_block_mock *mock)
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

	mock_set_name (&mock->mock, "mmio_register_block");

	mock->base.map = mmio_register_block_mock_map;
	mock->base.unmap = mmio_register_block_mock_unmap;
	mock->base.read32 = mmio_register_block_mock_read32;
	mock->base.write32 = mmio_register_block_mock_write32;
	mock->base.block_read32 = mmio_register_block_mock_block_read32;
	mock->base.block_write32 = mmio_register_block_mock_block_write32;

	mock->mock.func_arg_count = mmio_register_block_mock_func_arg_count;
	mock->mock.func_name_map = mmio_register_block_mock_func_name_map;
	mock->mock.arg_name_map = mmio_register_block_mock_arg_name_map;

	return 0;
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int mmio_register_block_mock_validate_and_release (struct mmio_register_block_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		mock_release (&mock->mock);
	}

	return status;
}
