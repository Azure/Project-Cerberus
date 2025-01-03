// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "ide_driver_mock.h"
#include "pcisig/ide/ide_driver.h"
#include "status/rot_status.h"


static int ide_driver_mock_get_bus_device_segment_info (
	const struct ide_driver *ide_driver, uint8_t port_index, uint8_t *bus_num,
	uint8_t *device_func_num, uint8_t *segment, uint8_t *max_port_index)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_get_bus_device_segment_info, ide_driver,
		MOCK_ARG_CALL (port_index), MOCK_ARG_PTR_CALL (bus_num),
		MOCK_ARG_PTR_CALL (device_func_num), MOCK_ARG_PTR_CALL (segment),
		MOCK_ARG_PTR_CALL (max_port_index));
}

static int ide_driver_mock_get_capability_register (
	const struct ide_driver *ide_driver, uint8_t port_index,
	struct ide_capability_register *capability_register)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_get_capability_register, ide_driver,
		MOCK_ARG_CALL (port_index), MOCK_ARG_PTR_CALL (capability_register));
}

static int ide_driver_mock_get_control_register (
	const struct ide_driver *ide_driver, uint8_t port_index,
	struct ide_control_register *control_register)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_get_control_register, ide_driver,
		MOCK_ARG_CALL (port_index), MOCK_ARG_PTR_CALL (control_register));
}

static int ide_driver_mock_get_link_ide_register_block (
	const struct ide_driver *ide_driver, uint8_t port_index, uint8_t block_idx,
	struct ide_link_ide_stream_register_block *register_block)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_get_link_ide_register_block, ide_driver,
		MOCK_ARG_CALL (port_index), MOCK_ARG_CALL (block_idx), MOCK_ARG_PTR_CALL (register_block));
}

static int ide_driver_mock_get_selective_ide_stream_register_block (
	const struct ide_driver *ide_driver, uint8_t port_index, uint8_t block_idx,
	struct ide_selective_ide_stream_register_block *register_block)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_get_selective_ide_stream_register_block, ide_driver,
		MOCK_ARG_CALL (port_index), MOCK_ARG_CALL (block_idx), MOCK_ARG_PTR_CALL (register_block));
}

static int ide_driver_mock_key_prog (
	const struct ide_driver *ide_driver, uint8_t port_index, uint8_t stream_id,	uint8_t key_set,
	bool tx_key, uint8_t key_substream, const uint32_t *key, uint32_t key_size,	const uint32_t *iv,
	uint32_t iv_size)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_key_prog, ide_driver,	MOCK_ARG_CALL (port_index),
		MOCK_ARG_CALL (stream_id), MOCK_ARG_CALL (key_set),	MOCK_ARG_CALL (tx_key),
		MOCK_ARG_CALL (key_substream), MOCK_ARG_PTR_CALL (key),	MOCK_ARG_CALL (key_size),
		MOCK_ARG_PTR_CALL (iv), MOCK_ARG_CALL (iv_size));
}

static int ide_driver_mock_key_set_go (
	const struct ide_driver *ide_driver, uint8_t port_index, uint8_t stream_id,	uint8_t key_set,
	bool tx_key, uint8_t key_substream)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_key_set_go, ide_driver, MOCK_ARG_CALL (port_index),
		MOCK_ARG_CALL (stream_id), MOCK_ARG_CALL (key_set),	MOCK_ARG_CALL (tx_key),
		MOCK_ARG_CALL (key_substream));
}

static int ide_driver_mock_key_set_stop (const struct ide_driver *ide_driver, uint8_t port_index,
	uint8_t stream_id, uint8_t key_set, bool tx_key, uint8_t key_substream)
{
	struct ide_driver_mock *mock = (struct ide_driver_mock*) ide_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ide_driver_mock_key_set_stop, ide_driver,	MOCK_ARG_CALL (port_index),
		MOCK_ARG_CALL (stream_id), MOCK_ARG_CALL (key_set),	MOCK_ARG_CALL (tx_key),
		MOCK_ARG_CALL (key_substream));
}

static int ide_driver_mock_func_arg_count (void *func)
{
	if (func == ide_driver_mock_get_bus_device_segment_info) {
		return 5;
	}
	else if (func == ide_driver_mock_get_capability_register) {
		return 2;
	}
	else if (func == ide_driver_mock_get_control_register) {
		return 2;
	}
	else if (func == ide_driver_mock_get_link_ide_register_block) {
		return 3;
	}
	else if (func == ide_driver_mock_get_selective_ide_stream_register_block) {
		return 3;
	}
	else if (func == ide_driver_mock_key_prog) {
		return 9;
	}
	else if (func == ide_driver_mock_key_set_go) {
		return 5;
	}
	else if (func == ide_driver_mock_key_set_stop) {
		return 5;
	}
	else {
		return 0;
	}
}

static const char* ide_driver_mock_arg_name_map (void *func, int arg)
{
	if (func == ide_driver_mock_get_bus_device_segment_info) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "bus_num";

			case 2:
				return "device_func_num";

			case 3:
				return "segment";

			case 4:
				return "max_port_index";
		}
	}
	else if (func == ide_driver_mock_get_capability_register) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "capability_register";
		}
	}
	else if (func == ide_driver_mock_get_control_register) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "control_register";
		}
	}
	else if (func == ide_driver_mock_get_link_ide_register_block) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "block_idx";

			case 2:
				return "register_block";
		}
	}
	else if (func == ide_driver_mock_get_selective_ide_stream_register_block) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "block_idx";

			case 2:
				return "register_block";
		}
	}
	else if (func == ide_driver_mock_key_prog) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "stream_id";

			case 2:
				return "key_set";

			case 3:
				return "tx_key";

			case 4:
				return "key_substream";

			case 5:
				return "key";

			case 6:
				return "key_size";

			case 7:
				return "iv";

			case 8:
				return "iv_size";
		}
	}
	else if (func == ide_driver_mock_key_set_go) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "stream_id";

			case 2:
				return "key_set";

			case 3:
				return "tx_key";

			case 4:
				return "key_substream";
		}
	}
	else if (func == ide_driver_mock_key_set_stop) {
		switch (arg) {
			case 0:
				return "port_index";

			case 1:
				return "stream_id";

			case 2:
				return "key_set";

			case 3:
				return "tx_key";

			case 4:
				return "key_substream";
		}
	}

	return "unknown";
}

static const char* ide_driver_mock_func_name_map (void *func)
{
	if (func == ide_driver_mock_get_bus_device_segment_info) {
		return "get_bus_device_segment_info";
	}
	else if (func == ide_driver_mock_get_capability_register) {
		return "get_capability_register";
	}
	else if (func == ide_driver_mock_get_control_register) {
		return "get_control_register";
	}
	else if (func == ide_driver_mock_get_link_ide_register_block) {
		return "get_link_ide_register_block";
	}
	else if (func == ide_driver_mock_get_selective_ide_stream_register_block) {
		return "get_selective_ide_stream_register_block";
	}
	else if (func == ide_driver_mock_key_prog) {
		return "key_prog";
	}
	else if (func == ide_driver_mock_key_set_go) {
		return "key_set_go";
	}
	else if (func == ide_driver_mock_key_set_stop) {
		return "key_set_stop";
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize a mock IDE driver for programming IDE registers.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int ide_driver_mock_init (struct ide_driver_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ide_driver_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ide_driver");

	mock->base.get_bus_device_segment_info =
		ide_driver_mock_get_bus_device_segment_info;
	mock->base.get_capability_register = ide_driver_mock_get_capability_register;
	mock->base.get_control_register = ide_driver_mock_get_control_register;
	mock->base.get_link_ide_register_block =
		ide_driver_mock_get_link_ide_register_block;
	mock->base.get_selective_ide_stream_register_block =
		ide_driver_mock_get_selective_ide_stream_register_block;
	mock->base.key_prog = ide_driver_mock_key_prog;
	mock->base.key_set_go = ide_driver_mock_key_set_go;
	mock->base.key_set_stop = ide_driver_mock_key_set_stop;

	mock->mock.func_arg_count = ide_driver_mock_func_arg_count;
	mock->mock.func_name_map = ide_driver_mock_func_name_map;
	mock->mock.arg_name_map = ide_driver_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a ide driver interface mock.
 *
 * @param mock The mock to release.
 */
void ide_driver_mock_release (struct ide_driver_mock *mock)
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
int ide_driver_mock_validate_and_release (struct ide_driver_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ide_driver_mock_release (mock);
	}

	return status;
}
