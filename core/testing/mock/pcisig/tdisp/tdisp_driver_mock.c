// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "tdisp_driver_mock.h"
#include "pcisig/tdisp/tdisp_driver.h"
#include "status/rot_status.h"

static int tdisp_driver_mock_get_function_index (const struct tdisp_driver *tdisp_driver,
	uint32_t bdf, uint32_t *function_index)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_get_function_index, tdisp_driver,
		MOCK_ARG_CALL (bdf), MOCK_ARG_PTR_CALL (function_index));
}

static int tdisp_driver_mock_get_tdisp_capabilities (const struct tdisp_driver *tdisp_driver,
	const struct tdisp_requester_capabilities *req_caps,
	struct tdisp_responder_capabilities *rsp_caps)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_get_tdisp_capabilities, tdisp_driver,
		MOCK_ARG_PTR_CALL (req_caps), MOCK_ARG_PTR_CALL (rsp_caps));
}

static int tdisp_driver_mock_lock_interface_request (const struct tdisp_driver *tdisp_driver,
	uint32_t function_id, const struct tdisp_lock_interface_param *lock_interface_param)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_lock_interface_request, tdisp_driver,
		MOCK_ARG_CALL (function_id), MOCK_ARG_PTR_CALL (lock_interface_param));
}

static int tdisp_driver_mock_get_device_interface_report (const struct tdisp_driver *tdisp_driver,
	uint32_t function_id, uint16_t request_offset, uint16_t request_length,	uint16_t *report_length,
	uint8_t *interface_report, uint16_t *remainder_length)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_get_device_interface_report, tdisp_driver,
		MOCK_ARG_CALL (function_id), MOCK_ARG_CALL (request_offset), MOCK_ARG_CALL (request_length),
		MOCK_ARG_PTR_CALL (report_length), MOCK_ARG_PTR_CALL (interface_report),
		MOCK_ARG_PTR_CALL (remainder_length));
}

static int tdisp_driver_mock_get_device_interface_state (const struct tdisp_driver *tdisp_driver,
	uint32_t function_id, uint8_t *tdi_state)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_get_device_interface_state, tdisp_driver,
		MOCK_ARG_CALL (function_id), MOCK_ARG_PTR_CALL (tdi_state));
}

static int tdisp_driver_mock_start_interface_request (const struct tdisp_driver *tdisp_driver,
	uint32_t function_id)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_start_interface_request, tdisp_driver,
		MOCK_ARG_CALL (function_id));
}

static int tdisp_driver_mock_stop_interface_request (const struct tdisp_driver *tdisp_driver,
	uint32_t function_id)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_stop_interface_request, tdisp_driver,
		MOCK_ARG_CALL (function_id));
}

static int tdisp_driver_mock_get_mmio_ranges (const struct tdisp_driver *tdisp_driver,
	uint32_t function_id, uint32_t mmio_range_count, struct tdisp_mmio_range *mmio_ranges)
{
	struct tdisp_driver_interface_mock *mock = (struct tdisp_driver_interface_mock*) tdisp_driver;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_driver_mock_get_mmio_ranges, tdisp_driver,
		MOCK_ARG_CALL (function_id), MOCK_ARG_CALL (mmio_range_count),
		MOCK_ARG_PTR_CALL (mmio_ranges));
}

static int tdisp_driver_mock_func_arg_count (void *func)
{
	if (func == tdisp_driver_mock_get_function_index) {
		return 2;
	}
	else if (func == tdisp_driver_mock_get_tdisp_capabilities) {
		return 2;
	}
	else if (func == tdisp_driver_mock_lock_interface_request) {
		return 2;
	}
	else if (func == tdisp_driver_mock_get_device_interface_report) {
		return 6;
	}
	else if (func == tdisp_driver_mock_get_device_interface_state) {
		return 2;
	}
	else if (func == tdisp_driver_mock_start_interface_request) {
		return 1;
	}
	else if (func == tdisp_driver_mock_stop_interface_request) {
		return 1;
	}
	else if (func == tdisp_driver_mock_get_mmio_ranges) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* tdisp_driver_mock_arg_name_map (void *func, int arg)
{
	if (func == tdisp_driver_mock_get_function_index) {
		switch (arg) {
			case 0:
				return "bdf";

			case 1:
				return "function_index";
		}
	}
	else if (func == tdisp_driver_mock_get_tdisp_capabilities) {
		switch (arg) {
			case 0:
				return "req_caps";

			case 1:
				return "rsp_caps";
		}
	}
	else if (func == tdisp_driver_mock_lock_interface_request) {
		switch (arg) {
			case 0:
				return "function_id";

			case 1:
				return "lock_interface_param";
		}
	}
	else if (func == tdisp_driver_mock_get_device_interface_report) {
		switch (arg) {
			case 0:
				return "function_id";

			case 1:
				return "request_offset";

			case 2:
				return "request_length";

			case 3:
				return "report_length";

			case 4:
				return "interface_report";

			case 5:
				return "remainder_length";
		}
	}
	else if (func == tdisp_driver_mock_get_device_interface_state) {
		switch (arg) {
			case 0:
				return "function_id";

			case 1:
				return "tdi_state";
		}
	}
	else if (func == tdisp_driver_mock_start_interface_request) {
		switch (arg) {
			case 0:
				return "function_id";
		}
	}
	else if (func == tdisp_driver_mock_stop_interface_request) {
		switch (arg) {
			case 0:
				return "function_id";
		}
	}
	else if (func == tdisp_driver_mock_get_mmio_ranges) {
		switch (arg) {
			case 0:
				return "function_id";

			case 1:
				return "mmio_range_count";

			case 2:
				return "mmio_ranges";
		}
	}

	return "unknown";
}

static const char* tdisp_driver_mock_func_name_map (void *func)
{
	if (func == tdisp_driver_mock_get_function_index) {
		return "get_function_index";
	}
	else if (func == tdisp_driver_mock_get_tdisp_capabilities) {
		return "get_tdisp_capabilities";
	}
	else if (func == tdisp_driver_mock_lock_interface_request) {
		return "lock_interface_request";
	}
	else if (func == tdisp_driver_mock_get_device_interface_report) {
		return "get_device_interface_report";
	}
	else if (func == tdisp_driver_mock_get_device_interface_state) {
		return "get_device_interface_state";
	}
	else if (func == tdisp_driver_mock_start_interface_request) {
		return "start_interface_request";
	}
	else if (func == tdisp_driver_mock_stop_interface_request) {
		return "stop_interface_request";
	}
	else if (func == tdisp_driver_mock_get_mmio_ranges) {
		return "get_mmio_ranges";
	}

	return "unknown";
}


/**
 * Initialize a mock TDISP driver for programming TDISP registers.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int tdisp_driver_interface_mock_init (struct tdisp_driver_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct tdisp_driver_interface_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "tdisp_driver");

	mock->base.get_function_index = tdisp_driver_mock_get_function_index;
	mock->base.get_tdisp_capabilities = tdisp_driver_mock_get_tdisp_capabilities;
	mock->base.lock_interface_request = tdisp_driver_mock_lock_interface_request;
	mock->base.get_device_interface_report = tdisp_driver_mock_get_device_interface_report;
	mock->base.get_device_interface_state = tdisp_driver_mock_get_device_interface_state;
	mock->base.start_interface_request = tdisp_driver_mock_start_interface_request;
	mock->base.stop_interface_request = tdisp_driver_mock_stop_interface_request;
	mock->base.get_mmio_ranges = tdisp_driver_mock_get_mmio_ranges;

	mock->mock.func_arg_count = tdisp_driver_mock_func_arg_count;
	mock->mock.func_name_map = tdisp_driver_mock_func_name_map;
	mock->mock.arg_name_map = tdisp_driver_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a tdisp driver interface mock.
 *
 * @param mock The mock to release.
 */
void tdisp_driver_interface_mock_release (struct tdisp_driver_interface_mock *mock)
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
int tdisp_driver_interface_mock_validate_and_release (struct tdisp_driver_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		tdisp_driver_interface_mock_release (mock);
	}

	return status;
}
