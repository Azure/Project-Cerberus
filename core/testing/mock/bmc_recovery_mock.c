// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "bmc_recovery_mock.h"


static void bmc_recovery_mock_on_host_reset (struct bmc_recovery *recovery)
{
	struct bmc_recovery_mock *mock = (struct bmc_recovery_mock*) recovery;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, bmc_recovery_mock_on_host_reset, recovery);
}

static void bmc_recovery_mock_on_host_out_of_reset (struct bmc_recovery *recovery)
{
	struct bmc_recovery_mock *mock = (struct bmc_recovery_mock*) recovery;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, bmc_recovery_mock_on_host_out_of_reset, recovery);
}

static void bmc_recovery_mock_on_host_cs0 (struct bmc_recovery *recovery)
{
	struct bmc_recovery_mock *mock = (struct bmc_recovery_mock*) recovery;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, bmc_recovery_mock_on_host_cs0, recovery);
}

static int bmc_recovery_mock_on_host_cs1 (struct bmc_recovery *recovery, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	struct bmc_recovery_mock *mock = (struct bmc_recovery_mock*) recovery;

	if (mock == NULL) {
		return 0;
	}

	MOCK_RETURN (&mock->mock, bmc_recovery_mock_on_host_cs1, recovery, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (rsa));
}

static int bmc_recovery_mock_func_arg_count (void *func)
{
	if (func == bmc_recovery_mock_on_host_cs1) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* bmc_recovery_mock_func_name_map (void *func)
{
	if (func == bmc_recovery_mock_on_host_reset) {
		return "on_host_reset";
	}
	else if (func == bmc_recovery_mock_on_host_out_of_reset) {
		return "on_host_out_of_reset";
	}
	else if (func == bmc_recovery_mock_on_host_cs0) {
		return "on_host_cs0";
	}
	else if (func == bmc_recovery_mock_on_host_cs1) {
		return "on_host_cs1";
	}
	else {
		return "unknown";
	}
}

static const char* bmc_recovery_mock_arg_name_map (void *func, int arg)
{
	if (func == bmc_recovery_mock_on_host_cs1) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "rsa";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock state machine for BMC recovery.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock successfully initialized or an error code.
 */
int bmc_recovery_mock_init (struct bmc_recovery_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct bmc_recovery_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "bmc_recovery");

	mock->base.on_host_reset = bmc_recovery_mock_on_host_reset;
	mock->base.on_host_out_of_reset = bmc_recovery_mock_on_host_out_of_reset;
	mock->base.on_host_cs0 = bmc_recovery_mock_on_host_cs0;
	mock->base.on_host_cs1 = bmc_recovery_mock_on_host_cs1;

	mock->mock.func_arg_count = bmc_recovery_mock_func_arg_count;
	mock->mock.func_name_map = bmc_recovery_mock_func_name_map;
	mock->mock.arg_name_map = bmc_recovery_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by mock recovery state machine.
 *
 * @param mock The mock to release.
 */
void bmc_recovery_mock_release (struct bmc_recovery_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify that a mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int bmc_recovery_mock_validate_and_release (struct bmc_recovery_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		bmc_recovery_mock_release (mock);
	}

	return status;
}
