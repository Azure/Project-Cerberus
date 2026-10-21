// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "attestation_discover_mock.h"


static int attestation_discover_mock_discover_device (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation_requester)
{
	struct attestation_discover_mock *mock =
		(struct attestation_discover_mock*) attestation_discover;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_discover_mock_discover_device, attestation_discover,
		MOCK_ARG_PTR_CALL (attestation_requester));
}

static int attestation_discover_mock_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num)
{
	struct attestation_discover_mock *mock =
		(struct attestation_discover_mock*) attestation_discover;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_discover_mock_get_device_eid_by_device_num,
		attestation_discover, MOCK_ARG_PTR_CALL (attestation), MOCK_ARG_CALL (device_num));
}

static int attestation_discover_mock_func_arg_count (void *func)
{
	if (func == attestation_discover_mock_get_device_eid_by_device_num) {
		return 2;
	}
	else if (func == attestation_discover_mock_discover_device) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* attestation_discover_mock_func_name_map (void *func)
{
	if (func == attestation_discover_mock_discover_device) {
		return "discover_device";
	}
	else if (func == attestation_discover_mock_get_device_eid_by_device_num) {
		return "get_device_eid_by_device_num";
	}
	else {
		return "unknown";
	}
}

static const char* attestation_discover_mock_arg_name_map (void *func, int arg)
{
	if (func == attestation_discover_mock_discover_device) {
		switch (arg) {
			case 0:
				return "attestation_requester";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_discover_mock_get_device_eid_by_device_num) {
		switch (arg) {
			case 0:
				return "attestation";

			case 1:
				return "device_num";

			default:
				return "unknown";
		}
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize a mock for the attestation discover API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int attestation_discover_mock_init (struct attestation_discover_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct attestation_discover_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "attestation_discover");

	mock->base.discover_device = attestation_discover_mock_discover_device;
	mock->base.get_device_eid_by_device_num =
		attestation_discover_mock_get_device_eid_by_device_num;

	mock->mock.func_arg_count = attestation_discover_mock_func_arg_count;
	mock->mock.func_name_map = attestation_discover_mock_func_name_map;
	mock->mock.arg_name_map = attestation_discover_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock attestation discover API instance.
 *
 * @param mock The mock to release.
 */
void attestation_discover_mock_release (struct attestation_discover_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that a mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int attestation_discover_mock_validate_and_release (struct attestation_discover_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		attestation_discover_mock_release (mock);
	}

	return status;
}
